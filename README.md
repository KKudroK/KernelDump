# KernelDump

KernelDump는 **실행 중인 Linux 커널 메모리를 골라 파일로 저장하는 도구**입니다. 커널은 프로세스, 메모리, 파일, 통신을 관리하는 운영체제의 핵심 부분입니다. 버전은 **1.4.0**입니다.

한 번 실행하면 준비 검사, 수집, 결과 구조 검사를 순서대로 진행합니다. 커널 모듈을 설치하거나 프로세스를 멈추지 않습니다. 전체 RAM을 저장하는 도구는 아닙니다.

[다운로드](https://github.com/KKudroK/KernelDump/releases/latest) · [빠른 시작](#빠른-시작) · [Pod 지정](#pod를-지정할-때) · [결과 확인](#결과-확인) · [코드와 수집 원리](docs/CODEBASE_GUIDE.md)

## 실행 조건

- Linux x86-64, little-endian, 4KiB 페이지 환경에서 실행합니다. 공개 바이너리는 ARM64용이 아닙니다.
- 수집할 **노드의 호스트에서** 실행합니다. `/proc/kcore`, `/proc/kpageflags`, `/proc/iomem`, `/proc/kallsyms`, `/sys/kernel/btf/vmlinux`를 읽을 수 있어야 합니다. BTF는 실행 중인 커널의 자료 크기와 위치를 알려 주는 정보입니다.
- 일반적으로 `sudo`를 사용합니다. `sudo`로 실행해도 커널 기능이나 보안 정책이 접근을 막으면 수집할 수 없습니다. 도구가 보안 설정을 자동으로 바꾸지는 않습니다.
- 출력에는 Linux 파일 권한, 파일·디렉터리 `fsync`, 덮어쓰기 없는 파일 게시를 지원하는 저장소가 필요합니다. 최소 여유 공간 검사는 RAM의 10%와 1GiB 중 큰 값을 사용합니다. 실제 덤프가 그보다 클 수 있으므로 충분한 공간을 준비하세요.

실행 파일 하나로 동작합니다. 수집 노드에 Rust, Python, 별도 라이브러리나 ISF를 설치할 필요는 없습니다. ISF는 이후 분석에 사용하는 커널 자료 형식 파일입니다.

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

`/evidence` 대신 준비한 저장소 경로를 사용할 수 있습니다. 부모 디렉터리는 미리 만들고, 결과 디렉터리는 새 이름을 사용합니다.

```sh
sudo install -d -m 700 /evidence
sudo ./kerneldump --output /evidence/kernel_001
result=$?
printf '종료 코드: %s\n' "$result"
```

수집 직후 검사는 LiME 헤더, 수집 범위 기록, 파일 길이와 개수를 대조합니다. **메모리 파일 전체를 다시 읽는 SHA-256 검사는 아닙니다.** 출력의 `verification_mode`는 `fast_header_ledger`, `payload_hash_verified`는 `false`입니다.

### 3. 전체 파일 검사하기

저장된 메모리 파일을 다시 읽어 SHA-256까지 검사하려면 실행합니다. 새로 메모리를 수집하지 않으므로 원래 노드가 아닌 Linux PC에서도 검사할 수 있습니다. 아래의 `sudo`는 소유자 전용 결과 파일을 읽기 위해 사용합니다.

```sh
sudo ./kerneldump verify --output /evidence/kernel_001
```

전체 검사를 통과하면 `mode: full_sha256`, `payload_hash_verified: true`가 나옵니다. 파일을 다른 저장소로 복사한 뒤에도 같은 명령으로 확인할 수 있습니다.

## Pod를 지정할 때

`--pod`는 **추가 실행 코드·소켓·파일 캐시 탐색만** 해당 Pod로 좁힙니다. 기본 커널 메모리 수집 범위는 노드 전체입니다. 지정한 Pod의 메모리만 들어 있는 파일이라고 해석하면 안 됩니다.

`kubectl`을 사용할 수 있는 곳에서 Pod UID와 노드를 확인합니다. `default`와 `my-pod`는 실제 값으로 바꾸세요.

```sh
kubectl get pod -n default my-pod   -o jsonpath='{.metadata.uid}{"\n"}{.spec.nodeName}{"\n"}'
```

첫 줄의 전체 Pod UID를 넣고, 둘째 줄에 나온 노드에서 수집합니다. Pod 이름이나 UID 일부는 사용할 수 없습니다.

```sh
POD_UID='여기에-전체-Pod-UID'
sudo ./kerneldump --output /evidence/kernel_pod_001 --pod "$POD_UID"
```

Pod의 살아 있는 프로세스를 찾지 못하면 기본적으로 중단합니다. 종료된 Pod를 조사하며 기본 커널 수집을 계속하려는 경우에만 다음 옵션을 함께 사용합니다. 이 옵션이 Pod의 과거 존재나 소속을 증명하지는 않습니다. UID가 잘못되어도 현재 프로세스가 없을 수 있습니다.

```sh
sudo ./kerneldump --output /evidence/kernel_exited_001   --pod "$POD_UID" --allow-exited-pod
```

`--pod`를 쓸 때는 호스트 PID·cgroup namespace인지 검사합니다. namespace는 프로세스 등이 볼 수 있는 범위를 구분하는 Linux 기능입니다. WSL2의 중첩 namespace 등에서 검사에 실패하면 수집하지 않습니다. `--allow-exited-pod`로 이 검사를 건너뛸 수는 없습니다.

## 결과 확인

| 파일 | 내용 |
|---|---|
| `memory.lime` | 물리 주소와 함께 저장한 메모리. LiME는 메모리 구간의 주소와 바이트를 담는 파일 형식입니다. |
| `ranges.jsonl` | 수집, 정책에 따른 제외, 읽기 실패, 미처리 범위 |
| `manifest.json` | 커널 식별 정보, 수집 정책, 상태, 오류, 파일 크기와 SHA-256 |
| `memory.lime.partial` | 수집·저장이 끝나지 않은 메모리 파일 |

세 결과 파일을 같은 디렉터리에 둡니다. `memory.lime`만 옮기면 전체 검증에 필요한 수집 기록이 빠집니다.

| 종료 코드 | 뜻 | 다음 행동 |
|---:|---|---|
| `0` | 수집 명령은 정책에 따른 완료·저장·구조 검사 성공. `verify`는 전체 검사 성공 및 완료 상태 확인 | 파일과 수집 기록을 함께 보관합니다. |
| `2` | 일부만 수집했거나 `verify`한 수집본이 불완전함 | `errors`, `unavailable_bytes`, `unprocessed_bytes`를 확인합니다. |
| `1` | 인자·준비·접근·저장·검증 오류 | 터미널 오류를 확인합니다. 남은 파일을 완료본으로 취급하지 않습니다. |

`complete_for_policy`는 정해진 정책에 따른 완료입니다. 전체 RAM이나 모든 증거를 확보했다는 뜻은 아닙니다. 수집 중 커널과 프로세스는 계속 움직이므로 모든 바이트가 같은 순간의 값인 것도 아닙니다.

## 옵션

```sh
./kerneldump --help
```

| 옵션 | 사용 방법 |
|---|---|
| `--output NEW_DIR` | 필수. 새 수집 디렉터리. `verify`에서는 기존 결과 디렉터리를 지정합니다. |
| `--pod FULL_POD_UID` | 추가 탐색을 지정 Pod로 좁힙니다. 기본 커널 수집은 노드 전체입니다. |
| `--allow-exited-pod` | `--pod`와 함께 사용. 현재 소속 프로세스가 없어도 기본 커널 수집을 진행합니다. |
| `--request-id ID` | 요청을 구별할 이름을 기록합니다. 영문·숫자·`-_.:`로 1~128자를 사용합니다. 중복 작업을 자동 연결하는 기능은 아닙니다. |
| `--max-write-mbps 1..10000` | 메모리 본문 쓰기 평균 속도 제한. `1`은 초당 1,000,000바이트입니다. 헤더·수집 기록과 파일 시스템 자체 쓰기는 별도입니다. |
| `--version`, `--build-info` | 버전 또는 빌드·실행 파일 정보를 확인합니다. |

```sh
sudo ./kerneldump --output /evidence/kernel_002 --max-write-mbps 200
```

쓰기는 묶어서 진행하므로 짧은 순간에는 설정값보다 빠를 수 있습니다. 제한이 낮으면 수집이 오래 걸리고 수집 도중 바뀌는 메모리가 늘 수 있습니다.

## 수집 범위

- 커널의 프로세스·파일·통신 등을 분석하는 데 필요한 메모리를 선별합니다. 일반 프로세스 메모리 전체와 일반 파일 캐시 전체는 수집하지 않습니다.
- 일부 익명 실행 코드, 소켓 대기 내용, memfd·삭제 후 열린 파일 등의 캐시를 추가로 수집합니다. 세 종류가 합계 4,096페이지, 본문 최대 16MiB의 한도를 공유합니다. 한도나 접근 오류로 빠진 범위는 `partial`과 원인으로 남깁니다.
- Sparse 방식으로 0 페이지의 디스크 쓰기를 줄입니다. 파일을 읽으면 같은 0바이트가 나옵니다. 실제 절약량은 메모리 내용과 저장소에 따라 다릅니다.
- 프로세스 메모리까지 분석하려면 [PodDump](https://github.com/KKudroK/PodDump)의 Core·manifest와 해당 커널의 ISF도 준비합니다. 수집 결과와 일치하는 ISF를 사용해야 합니다.
- 기본 사용법은 단일 수집 명령입니다. 이전 `check --target-dir`, `capture --output`, `probe`, `verify DIR` 명령도 계속 사용할 수 있습니다. 새 스크립트의 별도 전체 검사는 `verify --output`을 사용하세요.

## 빌드와 상세 문서

소스에서 빌드할 때만 Rust와 Python 3가 필요합니다. 의존성 소스는 `vendor/`에 포함되어 있습니다.

```sh
rustup target add x86_64-unknown-linux-musl
cargo test --offline --locked
python3 scripts/build_release.py
```

결과는 `release/kerneldump`, `release/manifest.json`, `release/SHA256SUMS.txt`입니다. 공개 빌드에는 `development-options`를 켜지 않습니다.

- [코드와 수집 원리](docs/CODEBASE_GUIDE.md)
- [배포 조건](docs/deployment.md)
- [추가 수집 범위와 비용](docs/resource_retention.md)
- [배포판별 과거 검증](docs/distro_validation.md)
- [과거 성능 측정](docs/benchmark_summary.md)
- [Volatility 3의 과거 호환 검사](docs/plugin_compatibility.md)

MIT 라이선스입니다. 포함된 외부 의존성에는 각 프로젝트의 라이선스가 적용됩니다.
