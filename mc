#!/usr/bin/bash
set -e

# Hardcoded path
SCRIPT_DIR="${HOME}/.local/share/minecraft"
BINDMOUNT_TARGET="${HOME}/.minecraft"

# Derived path
SHARED_DOT_MINECRAFT="${SCRIPT_DIR}/dotminecraft"
FIREJAIL_CONFIG="${SCRIPT_DIR}/firejail-java-minecraft.conf"
GAMEDIR="${SCRIPT_DIR}/gamedir"
LAUNCHER_PY="${SCRIPT_DIR}/launcher.py"

cd "$SCRIPT_DIR"

# Parse arguments
OFFLINE_USERNAME=""
USE_JAVA8="NO"
PRINT_HELP="NO"
LIST_VERSIONS="NO"

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -p|--offline)
      OFFLINE_USERNAME="$2"
      shift # past argument
      shift # past value
      ;;
    -g|--gamedir)
      GAMEDIR="$SCRIPT_DIR/$2"
      shift # past argument
      shift # past value
      ;;
    -8|--java8)
      USE_JAVA8=YES
      shift # past argument
      ;;
    -j|--firejail)
      FIREJAIL_CONFIG="$2"
      shift # past argument
      shift # past value
      ;;
    -h|--help)
      PRINT_HELP=YES
      shift # past argument
      ;;
    -l|--list-version)
      LIST_VERSIONS=YES
      shift # past argument
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
  echo "  -p <offline_name> : offline mode player name"
  echo "  -g <gamedir>      : gamedir name in script dir"
  echo "  -8                : Use Java 8"
  echo "  -l                : list versions"
  echo "  -f <filejail_cfg> : Start game in firejail"
  echo "                      Default to ${SCRIPT_DIR}/firejail-java-minecraft.conf"
  echo "                      Set to empty to disable firejail"
  echo
  echo "The following files may be put inside the gamedir"
  echo "  custom_jvm_args.txt : ?"
  echo "  java_path.txt : ?"
  exit
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

launch_new_java_firejail() {
  if [[ "${OFFLINE_USERNAME}" != "" ]]; then
    EXTRA_LAUNCHER_PY_ARGS="--offline ${OFFLINE_USERNAME}"
  fi
  export PYTHONDONTWRITEBYTECODE=1
  ${LAUNCHER_PY} $EXTRA_LAUNCHER_PY_ARGS\
    --mode argfile --version ${VERSION} --dotmc_folder "${SHARED_DOT_MINECRAFT}"\
    --gamedir "${BINDMOUNT_TARGET}" --argfile="${GAMEDIR}/launch_argfile.txt"

  cd "${BINDMOUNT_TARGET}"
  ensure_file "custom_jvm_args.txt" $'-XX:+UseZGC\n-Xmx8G\n'
  ensure_file "java_path.txt" "/usr/bin/java"
  
  # Prepend custom JVM argument
  cat "custom_jvm_args.txt" "launch_argfile.txt" > "launch_argfile.txt.new"
  mv "launch_argfile.txt.new" "launch_argfile.txt"

  JAVA_BINARY="$(cat java_path.txt)"

  firejail --profile="${FIREJAIL_CONFIG}"\
    --whitelist="${SHARED_DOT_MINECRAFT}"\
    --whitelist="${BINDMOUNT_TARGET}"\
    --read-only="${SHARED_DOT_MINECRAFT}"\
    --read-write="${SHARED_DOT_MINECRAFT}/assets/skins"\
    -- ${JAVA_BINARY} "@${BINDMOUNT_TARGET}/launch_argfile.txt"
}

if [[ "${USE_JAVA8}" == "NO" ]]; then
  if [[ "${FIREJAIL_CONFIG}" == "" ]]; then
    not_support
  else
    launch_new_java_firejail
  fi
else
  if [[ "${FIREJAIL_CONFIG}" == "" ]]; then
    not_support
  else
    not_support
  fi
fi
