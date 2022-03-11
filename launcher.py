#!/usr/bin/python3
# Usage:
# ./launcher.py
# ./launcher.py --mode download --dotmc_folder . --version 1.17.1
# ./launcher.py --mode launch --dotmc_folder . --version 1.17.1 --gamedir gamedir
# java @launch_argfile.txt

from absl import app
from absl import flags
from pathlib import Path
import httplib2
import json
import hashlib
import subprocess
import uuid
import mslogin

FLAGS = flags.FLAGS
flags.DEFINE_enum(
    'mode', 'list', ['list', 'download', 'launch'], '''
list:     List all versions.
download: Download game files. Need `dotmc_folder` and `version`
launch:   Setup environment and export launch command. Need `dotmc_folder` and `version` and `gamedir`''')
flags.DEFINE_string("dotmc_folder", None, ".minecraft folder")
flags.DEFINE_string("version", None, "Minecraft version")
flags.DEFINE_string("gamedir", None, "Gamedir")
flags.DEFINE_string("launch_argfile", "launch_argfile.txt",
                    "Launch argument file, to use the file: `java @launch_argfile.txt`")
flags.DEFINE_string("offline", None, "Offline mode username")
flags.DEFINE_string("launch_jvm", None, "Start this JVM binary instead of writing the arg file.")
flags.DEFINE_list("launch_jvm_jvmarg", list(), "Extra JVM arguments if using launch_jvm")
flags.DEFINE_bool("overwrite_natives", False, "Extract native library files even when they exist")

http = httplib2.Http()

#======= helpers =======#


def httpget(url):
    print("Downloading", url)
    (resp, content) = http.request(url)
    assert resp["status"] == "200", "Failed to GET " + url
    return content


def download_file(url: str, dst: Path, hash=None):
    if dst.exists():
        # check hash if file exists
        if hash is not None:
            actual_hash = hashlib.sha1(open(dst, "rb").read()).hexdigest()
            if actual_hash == hash:
                return
        else:
            print(f"[warn] No HASH for {str(dst)}, cannot check integrity")

    # download and check hash
    dst.parent.mkdir(0o755, True, True)
    with open(dst, "wb") as f:
        f.write(httpget(url))
    if hash is not None:
        actual_hash = hashlib.sha1(open(dst, "rb").read()).hexdigest()
        assert hash == actual_hash, f"url={url} path={str(dst)} hash={hash} actual={actual_hash}"


#======= downloader =======#


def download_version_manifest():
    url = 'https://launchermeta.mojang.com/mc/game/version_manifest.json'
    return json.loads(httpget(url))


def download_version(versions_map, version):
    # Download .minecraft/versions/<version>
    p = Path(FLAGS.dotmc_folder) / "versions" / version
    config = p / (version + ".json")
    jar = p / (version + ".jar")
    p.mkdir(mode=0o755, parents=True, exist_ok=True)
    if not config.is_file():
        assert version in versions_map, f"Version {version} not found."
        v = versions_map[version]
        data = httpget(v["url"])
        data = json.dumps(json.loads(data), indent=2).encode()
        with open(config, "wb") as f:
            f.write(data)
    version_obj = json.load(open(config, "r"))
    if not jar.is_file():
        url = version_obj["downloads"]["client"]["url"]
        data = httpget(url)
        with open(jar, "wb") as f:
            f.write(data)
    assert jar.stat().st_size == version_obj["downloads"]["client"]["size"]
    actual_sha = hashlib.sha1(open(jar, "rb").read()).hexdigest()
    assert actual_sha == version_obj["downloads"]["client"]["sha1"]
    print("SHA1 check pass:", str(jar))
    if "inheritsFrom" in version_obj:
        download_version(versions_map, version_obj["inheritsFrom"])


def download_libraries(library_map):
    # Downloads .minecraft/libraries/*
    libdir = Path(FLAGS.dotmc_folder) / "libraries"
    for _lname, l in library_map.items():
        if "artifact" in l["downloads"]:
            p = libdir / l["downloads"]["artifact"]["path"]
            u = l["downloads"]["artifact"]["url"]
            h = l["downloads"]["artifact"]["sha1"]
            download_file(u, p, h)

        if "natives" in l:
            assert l["natives"]["linux"] == "natives-linux"
            obj = l["downloads"]["classifiers"]["natives-linux"]
            p = libdir / obj["path"]
            u = obj["url"]
            h = obj["sha1"]
            download_file(u, p, h)


def download_asset(version):
    # Read asset index from .minecraft/versions/<version>
    # Then download the assets.
    obj = load_merged_version_json(version)
    ai = obj["assetIndex"]

    p = Path(FLAGS.dotmc_folder) / "assets/indexes" / (ai["id"] + ".json")
    download_file(ai["url"], p, ai["sha1"])
    ai_obj = json.load(open(p, "r"))

    for _fname, info in ai_obj["objects"].items():
        h = info["hash"]
        u = f"http://resources.download.minecraft.net/{h[:2]}/{h}"
        p = Path(FLAGS.dotmc_folder) / f"assets/objects/{h[:2]}/{h}"
        download_file(u, p, h)


# ===== version.json rules helper ===== #


def parse_arguments_game_rules(rules):
    assert len(rules) == 1
    assert rules[0]["action"] == "allow"
    demo_rule = "is_demo_user" in rules[0]["features"]
    resolution_rule = "has_custom_resolution" in rules[0]["features"]
    assert demo_rule != resolution_rule
    return resolution_rule


def parse_arguments_jvm_rules(rules):
    assert len(rules) == 1
    assert rules[0]["action"] == "allow"
    if "arch" in rules[0]["os"]:
        assert rules[0]["os"]["arch"] == "x86"
    if "name" in rules[0]["os"]:
        assert rules[0]["os"]["name"] in {"windows", "osx"}
    return False


def parse_libraries_rules(rules):
    allow = dict(osx=False, linux=False, windows=False)
    disallow = dict(osx=False, linux=False, windows=False)
    for r in rules:
        if r["action"] == "allow":
            if "os" in r:
                allow[r["os"]["name"]] = True
            else:
                allow = dict(osx=True, linux=True, windows=True)
        else:
            if "os" in r:
                disallow[r["os"]["name"]] = True
            else:
                disallow = dict(osx=True, linux=True, windows=True)
    ret = dict()
    for x in ["osx", "linux", "windows"]:
        ret[x] = allow[x] and not disallow[x]
    return ret


# ===== version.json parser ===== #

VERSION_JSON_INHERIT_OVERWRITE = {
    "id", "time", "releaseTime", "type", "mainClass", "minecraftArguments", "main_jar_file_version"
}
VERSION_JSON_INHERIT_IGNORE = {"_comment_", "inheritsFrom", "logging"}
VERSION_JSON_INHERIT_SPECIAL = {"arguments", "libraries"}


def load_merged_version_json(version) -> "merged_version_json":
    this_version_json_path = Path(FLAGS.dotmc_folder) / "versions" / version / (version + ".json")
    assert this_version_json_path.is_file(), f"{version} not exists"
    obj = json.load(open(this_version_json_path, "r"))
    main_jar_file = Path(FLAGS.dotmc_folder) / "versions" / version / (version + ".jar")
    if main_jar_file.is_file():
        obj["main_jar_file_version"] = version

    if "inheritsFrom" in obj:
        base_obj = load_merged_version_json(obj["inheritsFrom"])
        for k, v in obj.items():
            if k in VERSION_JSON_INHERIT_IGNORE:
                continue
            elif k in VERSION_JSON_INHERIT_OVERWRITE:
                base_obj[k] = v
            elif k in VERSION_JSON_INHERIT_SPECIAL:
                if k == "libraries":
                    base_obj["libraries"] += v
                elif k == "arguments":
                    base_obj["arguments"]["game"] += v["game"]
                    base_obj["arguments"]["jvm"] += v["jvm"]
            else:
                assert False, f"unexpected inhertance field: {k}"
        return base_obj
    else:
        return obj


def compose_args(version) -> ('args_game list', 'args_jvm list'):
    # compose unsubstituted argument list for .minecraft/versions/<version>
    version_obj = load_merged_version_json(version)

    def walker(src, rule_checker, dst):
        for a in src:
            if type(a) is str:
                dst.append(a)
            elif rule_checker(a["rules"]):
                v = a["value"]
                if type(v) is str:
                    dst.append(v)
                else:
                    dst += v

    args_game = []
    args_jvm = []
    if "arguments" in version_obj:
        assert "minecraftArguments" not in version_obj
        walker(version_obj["arguments"]["game"], parse_arguments_game_rules, args_game)
        walker(version_obj["arguments"]["jvm"], parse_arguments_jvm_rules, args_jvm)
    else:
        assert "minecraftArguments" in version_obj
        args_jvm = r'-Djava.library.path=${natives_directory} -cp ${classpath}'.split(' ')
        args_game = version_obj["minecraftArguments"].split(' ')

    return args_game, args_jvm


def conflicting_library_resolution(library_map, group_and_name, incoming_lib):
    # A set of jars that forge wants to update
    FORGE_OVERWRITES = {
        "org.apache.commons:commons-lang3",
        "net.sf.jopt-simple:jopt-simple",
        "org.apache.logging.log4j:log4j-api",
        "org.apache.logging.log4j:log4j-core",
        "org.apache.logging.log4j:log4j-slf4j18-impl"
    }

    old_lib = library_map[group_and_name]
    if incoming_lib == old_lib:
        return

    if "natives" in incoming_lib and "natives" not in old_lib:
        library_map[group_and_name] = incoming_lib
    elif group_and_name in FORGE_OVERWRITES:
        library_map[group_and_name] = incoming_lib
    else:
        assert False, f"Duplicated library {group_and_name}\n{json.dumps(old_lib, indent=2)}\n{json.dumps(incoming_lib,indent=2)}"


def compose_cp(version) -> 'library_map':
    # Load the library map for .minecraft/versions/<version>
    obj = load_merged_version_json(version)

    library_map = dict()
    for l in obj["libraries"]:
        if "rules" in l and not parse_libraries_rules(l["rules"])["linux"]:
            continue
        nc = l["name"].split(":")
        assert len(nc) == 3
        lib_group_and_name = nc[0] + ":" + nc[1]
        if lib_group_and_name in library_map:
            conflicting_library_resolution(library_map, lib_group_and_name, l)
        else:
            library_map[lib_group_and_name] = l

    print("Classpaths:")
    for _lname, l in library_map.items():
        # format used by fabric
        if "url" in l:
            assert "downloads" not in l
            repo = l["url"]
            del l["url"]
            group, name, ver = l["name"].split(":")
            group_path = group.replace(".", "/")
            path = f"{group_path}/{name}/{ver}/{name}-{ver}.jar"
            url = f"{repo}{group_path}/{name}/{ver}/{name}-{ver}.jar"
            l["downloads"] = {"artifact":dict(url=url, path=path, sha1=None)}
        print(" ", l["name"], "[native]" if "natives" in l else "")

    return library_map


# ===== execution environment and launching ===== #


def extract_natives(library_map, version):
    # extract native binaries to .minecraft/versions/<version>/native
    libdir = Path(FLAGS.dotmc_folder) / "libraries"
    nativedir = Path(FLAGS.dotmc_folder) / "versions" / version / "native"
    if nativedir.exists() and not FLAGS.overwrite_natives:
        print("Native librarys exists, skip extraction.")
        return
    print("Extracting natives...")
    nativedir.mkdir(mode=0o755, parents=True, exist_ok=True)
    for _lname, l in library_map.items():
        if "natives" not in l: continue
        assert l["natives"]["linux"] == "natives-linux"
        native_obj = l["downloads"]["classifiers"]["natives-linux"]
        if "extract" in l: assert l["extract"] == dict(exclude=["META-INF/"])
        jarfile = libdir / native_obj["path"]
        actual_sha = hashlib.sha1(open(jarfile, "rb").read()).hexdigest()
        assert actual_sha == native_obj["sha1"]
        print(f"SHA1 OK: {jarfile.name}")
        subprocess.run(
            ["7z", "e", "-y",
             jarfile.resolve(), "-x!META-INF", "-x!*.git", "-x!*.sha1", f"-o{nativedir.resolve()}"],
            check=True,
            stdout=subprocess.DEVNULL)


def assemble_launch_args(version: str, gamedir: Path, user_credential: dict):
    obj = load_merged_version_json(version)
    assets_dir = (Path(FLAGS.dotmc_folder) / "assets").resolve()
    native_dir = (Path(FLAGS.dotmc_folder) / "versions" / version / "native").resolve()

    args = dict()

    # auth
    args["auth_player_name"] = user_credential["auth_player_name"]
    args["auth_uuid"] = user_credential["auth_uuid"]
    args["auth_access_token"] = user_credential["auth_access_token"]
    args["auth_xuid"] = user_credential["auth_xuid"]

    # misc info
    # forge requires that the version_name to be the official version name
    # args["version_name"] = obj["id"]
    args["game_directory"] = str(gamedir.resolve())
    args["assets_root"] = str(assets_dir)
    args["assets_index_name"] = obj["assets"]
    args["user_type"] = "mojang"
    args["version_type"] = obj["type"]
    args["launcher_name"] = "miencraft-launcher"
    args["launcher_version"] = "2.1.17627"
    args["clientid"] = str(uuid.uuid4())    # TODO: what's this?

    # w*h
    args["resolution_width"] = "1920"
    args["resolution_height"] = "1080"

    # natives
    args["natives_directory"] = str(native_dir)

    # forge special
    args["library_directory"] = str(Path(FLAGS.dotmc_folder) / "libraries")
    args["classpath_separator"] = ":"

    # classpath
    jars = []
    library_map = compose_cp(version)
    for _lname, l in library_map.items():
        if "artifact" in l["downloads"]:
            p = Path(FLAGS.dotmc_folder) / "libraries" / l["downloads"]["artifact"]["path"]
            assert p.is_file(), f"{p} not exists"
            jars.append(str(p.resolve()))
    main_jar_file_version = obj["main_jar_file_version"]
    p = Path(FLAGS.dotmc_folder) / "versions" / main_jar_file_version / (main_jar_file_version + ".jar")
    assert p.is_file(), f"{p} not exists"
    jars.append(str(p.resolve()))
    args["classpath"] = ":".join(jars)

    # nice try, forge
    args["version_name"] = main_jar_file_version

    #
    cmds = []
    args_game, args_jvm = compose_args(version)

    for a in args_jvm:
        for k, v in args.items():
            a = a.replace("${" + k + "}", v)
        cmds.append(a)
    
    # log4j2 vulnerability hotfix
    cmds.append("-Dlog4j2.formatMsgNoLookups=true")

    cmds.append(obj["mainClass"])
    for a in args_game:
        for k, v in args.items():
            a = a.replace("${" + k + "}", v)
        cmds.append(a)

    for a in cmds:
        print(a)

    return cmds
    # subprocess.run(cmds)


def main(argv):
    del argv

    # Create an empty launcher_profiles.json to make forge installer happy
    if FLAGS.dotmc_folder is not None:
        p = Path(FLAGS.dotmc_folder) / "launcher_profiles.json"
        if not p.exists():
            with open(p, "w") as f:
                json.dump(dict(profiles=dict()), f)

    if FLAGS.mode == "list":
        version_manifest = download_version_manifest()
        versions = reversed(version_manifest["versions"])
        for v in versions:
            s = "{type:<9} {id:<12} {url}".format(**v)
            print(s)
    elif FLAGS.mode == "download":
        assert FLAGS.dotmc_folder is not None
        assert FLAGS.version is not None

        version_manifest = download_version_manifest()
        versions_map = {v["id"]: v for v in version_manifest["versions"]}
        download_version(versions_map, FLAGS.version)

        library_map = compose_cp(FLAGS.version)
        download_libraries(library_map)
        download_asset(FLAGS.version)
    elif FLAGS.mode == 'launch':
        assert FLAGS.dotmc_folder is not None
        assert FLAGS.version is not None
        assert FLAGS.gamedir is not None
        assert (FLAGS.launch_argfile == "") != (FLAGS.launch_jvm is None)
        assert (Path(FLAGS.dotmc_folder) / "versions" / FLAGS.version /
                f"{FLAGS.version}.json").is_file(), f"Version {FLAGS.version} does not exists"

        # Download files in case missing anything
        library_map = compose_cp(FLAGS.version)
        download_libraries(library_map)
        download_asset(FLAGS.version)

        # Setup environment
        Path(FLAGS.gamedir).mkdir(0o755, True, True)
        extract_natives(library_map, FLAGS.version)

        # Login
        if FLAGS.offline is not None:
            user_credential = dict(
                auth_player_name=FLAGS.offline,
                auth_uuid="0",
                auth_access_token="0",
                auth_xuid="0",
            )
        else:
            auth_profile = mslogin.get_minecraft_accesstoken(mslogin.load_credential())
            user_credential = dict(
                auth_player_name=auth_profile.auth_player_name,
                auth_uuid=auth_profile.auth_uuid,
                auth_access_token=auth_profile.auth_access_token,
                auth_xuid=auth_profile.auth_xuid,
            )

        # Emit arguments
        launch_args = assemble_launch_args(FLAGS.version, Path(FLAGS.gamedir), user_credential)
        if FLAGS.launch_argfile != "":
            with open(FLAGS.launch_argfile, "w") as f:
                for x in launch_args:
                    # one argument per line, arg containing space should be quoted and escaped
                    escaped = x
                    if ' ' in x:
                        escaped = "\"" + x.replace("\\", "\\\\") + "\""
                    f.write(escaped + "\n")
        elif FLAGS.launch_jvm is not None:
            subprocess.run([FLAGS.launch_jvm] + FLAGS.launch_jvm_jvmarg + launch_args)


if __name__ == '__main__':
    app.run(main)
