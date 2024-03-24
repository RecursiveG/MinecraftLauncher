#!/usr/bin/bash
set -e

# Hardcoded path
SCRIPT_DIR="${HOME}/.local/share/minecraft"
BINDMOUNT_TARGET="${HOME}/.minecraft"

# Derived path
SHARED_DOT_MINECRAFT="${SCRIPT_DIR}/dotminecraft"
FIREJAIL_CONFIG="${SCRIPT_DIR}/firejail-java-minecraft.conf"
GAMEDIR=""
LAUNCHER_PY="${SCRIPT_DIR}/launcher.py"

cd "$SCRIPT_DIR"

# Parse arguments
OFFLINE_USERNAME=""
PRINT_HELP="NO"
LIST_VERSIONS="NO"
JAVA_EXECUTABLE="/usr/bin/java"

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -d|--open-folder)
      xdg-open "${SCRIPT_DIR}"
      exit
      ;;
    -f|--firejail)
      FIREJAIL_CONFIG="$2"
      shift # past argument
      shift # past value
      ;;
    -g|--gamedir)
      GAMEDIR="$SCRIPT_DIR/$2"
      shift # past argument
      shift # past value
      ;;
    -h|--help)
      PRINT_HELP=YES
      shift # past argument
      ;;
    -j|--java)
      JAVA_EXECUTABLE="$2"
      shift # past argument
      shift # past value
      ;;
    -l|--list-version)
      LIST_VERSIONS=YES
      shift # past argument
      ;;
    -p|--offline)
      OFFLINE_USERNAME="$2"
      shift # past argument
      shift # past value
      ;;
    *)    # unknown option
      POSITIONAL+=("$1") # save it in an array for later
      shift # past argument
      ;;
  esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [[ "$LIST_VERSIONS" == "YES" ]]; then
  ls -la "${SHARED_DOT_MINECRAFT}/versions"
  exit
fi

VERSION="$1"
if [[ "$VERSION" == "" || "$PRINT_HELP" == "YES" ]]; then
  echo "Usage: $0 [opts] <version>"
  echo "  -d                : Open in file browser: ${SCRIPT_DIR}"
  echo "  -f <filejail_cfg> : Start game in firejail"
  echo "                      Default to ${SCRIPT_DIR}/firejail-java-minecraft.conf"
  echo "                      Set to empty to disable firejail"
  echo "  -g <gamedir>      : Gamedir name in script dir"
  echo "  -h                : Print this help message"
  echo "  -j <path>         : Java executable. Default to /usr/bin/java"
  echo "  -l                : List versions"
  echo "  -p <offline_name> : Offline mode player name"
  echo
  echo "The following files may be put inside the gamedir"
  echo "  custom_jvm_args.txt : Extra JVM arguments to be prepended."
  echo "  extra_natives/      : Extra native binaries to be loaded."
  exit
fi

if [[ "$GAMEDIR" == "" ]]; then
  GAMEDIR="${SCRIPT_DIR}/gamedir_${VERSION}"
fi

mkdir -p "$SCRIPT_DIR"
mkdir -p "$BINDMOUNT_TARGET"
mkdir -p "$SHARED_DOT_MINECRAFT"
mkdir -p "$GAMEDIR"

echo "Selected version: ${VERSION}"
echo "Selected gamedir: ${GAMEDIR}"

# Bind mount gamedir to target
echo "Password for bind mount:"
sudo systemd-mount --unmount "${BINDMOUNT_TARGET}" || true
sudo systemd-mount -o bind "${GAMEDIR}" "${BINDMOUNT_TARGET}"

not_support() {
  echo "Not supported"
  exit
}

ensure_file() {
  FNAME="$1"
  DEFAULT_CONTENT="$2"
  if [[ ! -f "$FNAME" ]]; then
    echo -n "$DEFAULT_CONTENT" > "$FNAME"
  fi
}

launch_with_firejail() {
  if [[ "${OFFLINE_USERNAME}" != "" ]]; then
    EXTRA_LAUNCHER_PY_ARGS="--offline ${OFFLINE_USERNAME}"
  fi
  EXTRA_NATIVES=$(shopt -s nullglob; echo ${GAMEDIR}/extra_natives/* | tr ' ' ,)
  export PYTHONDONTWRITEBYTECODE=1
  ${LAUNCHER_PY} $EXTRA_LAUNCHER_PY_ARGS\
    --extra_natives "${EXTRA_NATIVES}"\
    --version ${VERSION} --dotmc_folder "${SHARED_DOT_MINECRAFT}"\
    --gamedir "${BINDMOUNT_TARGET}" --argfile="${GAMEDIR}/launch_argfile.txt"

  cd "${BINDMOUNT_TARGET}"
  ensure_file "custom_jvm_args.txt" $'-XX:+UseZGC\n-Xmx8G\n'
  
  # Prepend custom JVM argument
  cat "custom_jvm_args.txt" "launch_argfile.txt" > "launch_argfile.txt.new"
  mv "launch_argfile.txt.new" "launch_argfile.txt"

  firejail --profile="${FIREJAIL_CONFIG}"\
    --whitelist="${SHARED_DOT_MINECRAFT}"\
    --whitelist="${BINDMOUNT_TARGET}"\
    --read-only="${SHARED_DOT_MINECRAFT}"\
    --read-write="${SHARED_DOT_MINECRAFT}/assets/skins"\
    xargs -a launch_argfile.txt -d '\n' "${JAVA_EXECUTABLE}"
}

if [[ "${FIREJAIL_CONFIG}" == "" ]]; then
  not_support
else
  launch_with_firejail
fi
