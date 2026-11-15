# KernelDump

KernelDump는 **실행 중인 Linux 커널 메모리와 관련 커널·런타임 근거를 골라 LiME 파일로 저장하는 도구**입니다. 커널은 프로세스, 메모리, 파일, 통신을 관리하는 운영체제의 핵심 부분입니다. 버전은 **1.4.0**입니다.

한 번 실행하면 사전 검사, 수집, 결과 구조 검사를 순서대로 진행합니다. 커널 모듈을 설치하거나 프로세스를 멈추지 않습니다. 전체 RAM이나 일반 파일 캐시 전체를 저장하는 도구는 아닙니다.

[다운로드](https://github.com/KKudroK/KernelDump/releases/latest) · [빠른 시작](#빠른-시작) · [결과 확인](#결과-확인) · [코드와 수집 원리](docs/CODEBASE_GUIDE.md)

## 실행 조건

- Linux x86-64, little-endian, 4KiB 페이지 환경에서 실행합니다. 공개 바이너리는 ARM64용이 아닙니다.
- 수집할 **노드의 호스트에서** 실행합니다. `/proc/kcore`, `/proc/kpageflags`, `/proc/iomem`, `/proc/kallsyms`, `/sys/kernel/btf/vmlinux`를 읽을 수 있어야 합니다. BTF는 실행 중인 커널의 자료 크기와 위치를 알려 주는 정보입니다.
- 일반적으로 `sudo`를 사용합니다. `sudo`로 실행해도 커널 기능이나 보안 정책이 접근을 막으면 수집할 수 없습니다. 도구가 보안 설정을 자동으로 바꾸지는 않습니다.
- 출력에는 Linux 파일 권한, 파일·디렉터리 `fsync`, 덮어쓰기 없는 파일 게시를 지원하는 저장소가 필요합니다. 최소 여유 공간 검사는 RAM의 10%와 1GiB 중 큰 값을 사용합니다. 실제 덤프가 그보다 클 수 있으므로 충분한 공간을 준비하세요.

실행 파일 하나로 동작합니다. 수집 노드에 Rust, Python, 별도 라이브러리나 ISF를 설치할 필요는 없습니다. ISF는 이후 분석에 사용하는 커널 자료 형식 파일입니다.

## 이 도구를 쓰는 이유

[LiME](https://github.com/jtsylve/LiME)는 커널 모듈을 적재해 전체 메모리를 수집할 수 있습니다. KernelDump는 해당 노드의 BTF와 `/proc/kcore`를 읽으므로 별도 수집용 커널 모듈을 빌드·적재하지 않아도 됩니다. 대신 이 파일들에 접근할 수 있는 권한과 커널 기능이 필요합니다.

PodDump로 지정한 Pod의 메모리를 확보하고, KernelDump로 프로세스·파일·소켓 관계와 삭제된 파일·통신 대기열 같은 근거를 함께 확보하는 조사에 맞춥니다. 일반 파일 캐시 전체를 저장하지 않으며, 수집 범위·실패·상한 초과를 기록합니다. **전체 RAM 보존이 목적이라면 전체 수집 도구가 더 적합할 수 있습니다.** 이 도구의 선택 기준은 무조건 빠르다는 주장이 아니라 배치 방법과 조사에 필요한 수집 범위입니다.

메모리 기반 파일인 `/dev/shm`·Kubernetes `emptyDir: Memory`의 내용도 조사하려면 `--extended`를 사용하세요. 기본 모드는 경로가 남은 이 파일들의 내용을 추가 보존하지 않습니다. 확장 모드도 열린 파일 또는 공유 메모리 매핑에서 발견한 상주 페이지에 한하며, 노드의 모든 tmpfs 파일을 확보한다는 뜻은 아닙니다.

## 빠른 시작

### 1. 다운로드하고 확인하기

수집할 Linux 노드에서 실행합니다. 여기서 받는 `manifest.json`은 배포 파일의 빌드 정보입니다.

```sh
mkdir -p kerneldump_download
cd kerneldump_download
curl -fLO https://github.com/KKudroK/KernelDump/releases/download/v1.4.0/kerneldump
curl -fLO https://github.com/KKudroK/KernelDump/releases/download/v1.4.0/manifest.json
curl -fLO https://github.com/KKudroK/KernelDump/releases/download/v1.4.0/SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt
chmod 755 kerneldump
./kerneldump --version
```

`sha256sum`의 두 결과가 모두 `OK`인지 확인합니다. SHA-256은 파일 내용이 바뀌었는지 비교하는 데 쓰는 값입니다.

### 2. 수집하기

`/evidence` 대신 준비한 저장소 경로를 사용할 수 있습니다. 부모 디렉터리는 미리 만들고, 결과 디렉터리는 새 이름을 사용합니다. 별도 옵션 없이 노드 전체를 기준으로 수집합니다.

```sh
sudo install -d -m 700 /evidence
sudo ./kerneldump --output /evidence/kernel_001
result=$?
printf '종료 코드: %s\n' "$result"
```

수집 직후 구조 검사는 LiME 헤더, 수집 범위 기록, 파일 길이와 개수를 대조합니다. 출력의 `verification_mode`는 `fast_structural`, `payload_hash_verified`는 `false`입니다. 저장된 메모리 파일 전체 SHA-256까지 검증하려면 분석 단계에서 확인합니다.

## 결과 확인

| 파일 | 내용 |
|---|---|
| `memory.lime` | 물리 주소와 함께 저장한 메모리. LiME는 메모리 구간의 주소와 바이트를 담는 파일 형식입니다. |
| `ranges.jsonl` | 수집, 정책에 따른 제외, 읽기 실패, 미처리 범위 |
| `manifest.json` | 커널 식별 정보, 수집 정책, 상태, 오류, 파일 크기와 SHA-256 |
| `memory.lime.partial` | 수집·저장이 끝나지 않은 메모리 파일 |

세 결과 파일을 같은 디렉터리에 둡니다. `memory.lime`만 옮기면 검증에 필요한 수집 기록이 빠집니다.

| 종료 코드 | 뜻 | 다음 행동 |
|---:|---|---|
| `0` | 정책에 따른 완료·저장·구조 검사 성공 | 파일과 수집 기록을 함께 분석기에 전달합니다. |
| `2` | 일부만 수집했거나 구조 검사에서 불완전 상태 확인 | `errors`, `unavailable_bytes`, `unprocessed_bytes`를 확인합니다. |
| `1` | 인자·준비·접근·저장·검증 오류 | 터미널 오류를 확인합니다. 남은 파일을 완료본으로 취급하지 않습니다. |

`complete_for_policy`는 정해진 정책에 따른 완료입니다. 전체 RAM이나 모든 증거를 확보했다는 뜻은 아닙니다. 수집 중 커널과 프로세스는 계속 움직이므로 모든 바이트가 같은 순간의 값인 것도 아닙니다.

## 옵션

```sh
./kerneldump --help
```

| 옵션 | 사용 방법 |
|---|---|
| `--output NEW_DIR` | 필수. 새로 생성할 수집 결과 디렉터리 경로 |
| `--extended` | 선택. 기본 대상에 더해 경로가 남은 `tmpfs`(`0x01021994`, `/dev/shm` 등) 상주 페이지까지 추가로 수집 |
| `-h`, `--help` | 도움말 출력 후 종료 (인자 없이 실행해도 동일) |
| `-V`, `--version` | 버전 출력 후 종료 |

```sh
# 기본 수집: 비연결 파일·memfd, 실행 코드, 소켓 대기열 수집 (링크된 tmpfs 및 디스크 파일 제외)
sudo ./kerneldump --output /evidence/node_001

# 확장 수집: 기본 수집 + 링크가 남은 일반 tmpfs 상주 페이지 추가 (ext4 등 디스크 파일은 계속 제외)
sudo ./kerneldump --output /evidence/node_001 --extended
```

## 수집 범위

- 커널의 프로세스·파일·통신 등을 분석하는 데 필요한 SLAB·페이지 테이블과 인접 커널 페이지를 선별합니다. 일반 프로세스 메모리 전체와 디스크 파일 캐시(`ext4`, `xfs`, `overlayfs` 등) 전체는 제외합니다.
- 추가 증거는 Pod를 지정하지 않고 **노드 전체에서 조건에 맞는 대상만** 수집합니다.
  - 실행 중인 모든 프로세스의 private 실행 매핑(`r-xp`) 중 익명·COW 코드 페이지
  - 실행 커널 BTF를 따라 찾은 소켓 송신·수신 대기열과 TCP 재전송·비순차 큐(큐당 최대 `16 MiB`, 큐당 최대 `16,384`개 `sk_buff`, 전체 최대 `65,536`개 `sk_buff`)
  - 링크가 끊긴 정규 파일(`i_nlink == 0`, 예: `memfd_create`, `O_TMPFILE`, 삭제 후 열린 파일)의 상주 페이지: 열린 FD 또는 커널 VMA 트리에서 직접 찾은 공유 매핑을 대상으로 `address_space.i_pages` XArray 트리를 직접 순회해 앞부분 `16 MiB` 자름 없이 상주 페이지를 수집합니다(파일당 최대 `16,384` XArray 노드).
  - `--extended` 지정 시 링크가 남아 있는 `tmpfs`(`s_magic == 0x01021994`, 예: `/dev/shm`, `emptyDir: Memory`)의 상주 페이지도 열린 FD 또는 `MAP_SHARED` VMA를 통해 추가로 수집합니다.
  - 발견한 COW 실행 코드 페이지와 1:1로 대응하는 원본 파일 캐시 페이지
- 동시 작업 수, 쓰기 속도, 안전 상한(runaway 커널 방어용 공용 후보 `512 MiB` / `131,072`페이지, 소켓 큐 `16 MiB`)은 내부 기본값으로 자동 관리합니다. 상한에 걸려 일부가 잘리거나 읽기 오류가 나면 `queue_window_truncation`·`shared_retention_budget` 등의 `issues`와 `status: "partial"`(종료 코드 `2`)을 남기며 완료(`complete_for_policy`)로 보고하지 않습니다. 프로세스 정지 없이 수집하는 도중 대상 프로세스나 소켓 참조가 바뀐 경우에는 `ranges.jsonl`과 `live_drift`에 변경 사실을 함께 기록합니다.
- Sparse 방식으로 0 페이지의 디스크 쓰기를 줄입니다. 파일을 읽으면 같은 0바이트가 나옵니다.
- 프로세스 메모리까지 분석하려면 [PodDump](https://github.com/KKudroK/PodDump)의 Core·manifest와 해당 커널의 ISF도 준비합니다. 수집 결과와 일치하는 ISF를 사용해야 합니다.

## 빌드와 상세 문서

소스에서 빌드할 때만 Rust와 Python 3가 필요합니다. 의존성 소스는 `vendor/`에 포함되어 있습니다.

```sh
rustup target add x86_64-unknown-linux-musl
cargo test --offline --locked
python3 scripts/build_release.py
```

결과는 `release/kerneldump`, `release/manifest.json`, `release/SHA256SUMS.txt`입니다. 공개 빌드에는 별도 개발 옵션을 넣지 않습니다.

- [코드와 수집 원리](docs/CODEBASE_GUIDE.md)
- [배포 조건](docs/deployment.md)
- [추가 수집 범위와 비용](docs/resource_retention.md)
- [배포판별 과거 검증](docs/distro_validation.md)
- [과거 성능 측정](docs/benchmark_summary.md)
- [Volatility 3의 과거 호환 검사](docs/plugin_compatibility.md)

MIT 라이선스입니다. 포함된 외부 의존성에는 각 프로젝트의 라이선스가 적용됩니다.
