# KernelDump

[English](README.md) · [배포 조건](docs/deployment.md) · [측정 상세](docs/benchmark_summary.md)

`kerneldump`는 `/proc/kcore`와 `/proc/kpageflags`로 실행 중인 커널 메모리를 선별 수집합니다. 커널 모듈 설치나 프로세스 정지 없이 LiME 이미지, 주소·수집 범위 원장과 manifest를 만듭니다.

## 실행

Linux x86-64 정적 바이너리 하나로 실행합니다. 수집 시 별도 런타임 라이브러리·심볼·설정 파일이 필요하지 않습니다.

```sh
chmod 755 kerneldump
sudo ./kerneldump check --target-dir /evidence --json
sudo ./kerneldump capture --output /evidence/new_collection
./kerneldump verify /evidence/new_collection
```

`/evidence`는 기존 디렉터리, `new_collection`은 새 경로여야 합니다. `check`는 커널 접근과 임시 파일 생성·동기화·정리를 검사합니다. 저장소를 지정하지 않거나 검사에 실패하면 준비 실패를 반환합니다. 검사 통과는 공간 예약을 뜻하지 않습니다.

kcore/page monitor를 제공하는 커널과 필수 인터페이스·가려지지 않은 심볼에 대한 읽기 권한이 필요합니다. kcore가 없는 환경은 지원하지 않으며 보안 설정을 자동 변경하지 않습니다. [필수 조건과 실패 처리](docs/deployment.md).

## 검증한 환경

아래 환경에 동일한 x86-64 릴리즈 바이너리를 사용했습니다.

| 환경 | 커널 | 결과 |
|---|---|---|
| Ubuntu 24.04.5 | 6.8.0-147 | ext4에서 수집·검증 성공 |
| Ubuntu 26.04, WSL2 | 6.18.33.2 | ext4에서 수집·검증 성공 |
| Debian 12 | 6.1.0-53-cloud-amd64 | 수집·검증 성공; ext4, cgroup v2 |
| Debian 13 | 6.12.111+deb13-cloud-amd64 | 수집·검증 성공; ext4, cgroup v2 |
| Rocky Linux 8.10 | 4.18.0-553.el8_10.x86_64 | 수집·검증 성공; xfs, cgroup v1 |
| Rocky Linux 9.8 | 5.14.0-687.10.1.el9_8.0.1.x86_64 | 수집·검증 성공; xfs, cgroup v2 |
| Kali Rolling (cloud 2026.2) | 6.18.12+kali-cloud-amd64 | 수집·검증 성공; ext4, cgroup v2 |
| Alpine 3.16.9, cgroup v1 | 5.15.148 | 실행 가능, kcore 부재로 수집 불가 |
| Alpine 3.22.6, cgroup v2 | 6.12.110 | 실행 가능, kcore 부재로 수집 불가 |

Rocky는 SELinux Enforcing을 유지하고 unconfined 도메인에서 sudo로 실행했습니다. Alpine은 kcore가 없었고, WSL의 Windows 공유 저장소는 사적 권한 검사에 실패했습니다. [검증 조건](docs/distro_validation.md).

Kali cloud 이미지의 배포명은 2026.2이며, 내부 `VERSION_ID`는 2026.1입니다.

## 측정 결과

2026-10-16 같은 Ubuntu 노드·부팅에서 모드별 1회 수집한 기록입니다. 커널은 Linux 6.8.0-146이며, 표는 payload 크기와 수집기 경과 시간입니다.

| 방식 | Payload | 시간 |
|---|---:|---:|
| Full RAM | 9.663 GB | 38.27 s |
| KernelDump focused | 0.839 GB | 2.02 s |

선별 수집의 용량은 전체 RAM의 약 **8.7%**였습니다. 정책상 사용자·캐시·빈 페이지를 제외하므로 모든 조사에서 전체 RAM 수집을 대체하지는 않습니다. 두 수집의 시점도 다릅니다. [원본 manifest와 측정 방법](docs/benchmark_summary.md).

## 산출물과 종료 상태

- `memory.lime`: 물리 주소를 유지한 선별 메모리.
- `ranges.jsonl`: 수집·제외·읽기 실패 범위.
- `manifest.json`: 정책, 원본 식별 정보, 오류와 파일 해시.

종료 **0**은 기록된 정책에 따른 수집·저장 완료, **2**는 불완전 수집 또는 준비 실패, **1**은 명령·준비·검증·저장 오류입니다. stderr와 일부 파일을 보존하세요. 수집은 원자적이지 않으며 취소는 협력적입니다. SIGKILL 뒤에는 최종 manifest가 없을 수 있습니다.

## 빌드와 확인

```sh
./kerneldump --version
./kerneldump --build-info
# 빌드 호스트에만 Rust 1.90.0 + x86_64-unknown-linux-musl 타깃 필요
python3 scripts/build_release.py
```

버전 **0.1.1**. `release/kerneldump`와 선택적인 해시 증적을 만듭니다. 빌드 정보에는 소스 해시와 실제 실행 파일의 해시가 기록됩니다. [릴리즈 검증](docs/release_validation.md) · [이전 문서](docs/history_readme_20261017_ko.md).

MIT 라이선스이며, vendored 의존성은 각 라이선스를 유지합니다.
