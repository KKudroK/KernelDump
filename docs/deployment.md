# 배포 조건

현재 실행 조건과 명령은 [한국어 README](../README.md)에 있습니다. 공개 파일은 Linux x86-64 정적 바이너리입니다. 분석 입력이나 결과의 완전성은 수집 상태·오류·검사 범위를 함께 확인해야 합니다.

## 노드 준비

노드의 호스트 proc·cgroup을 사용하고, 수집 대상 읽기 권한을 확보합니다. 실행 파일만 복사한다고 필요한 권한이 생기지는 않습니다. 저장소는 소유자 전용 권한, 독점 파일 생성, `renameat2(RENAME_NOREPLACE)`, 파일·디렉터리 `fsync`를 지원해야 합니다. 출력 부모 디렉터리를 먼저 만들고 수집마다 새 경로를 사용합니다.

ext4에서 검사합니다. 네트워크 파일 시스템이나 WSL의 Windows 공유 경로가 같은 조건을 제공한다고 가정하지 않습니다. tmpfs는 재부팅 후 저장을 보장하지 않습니다. SIGKILL이나 저장 오류 뒤에 남은 파일은 완료본으로 취급하지 않습니다.

## 배포 파일 확인

다운로드한 실행 파일, 배포 `manifest.json`, `SHA256SUMS.txt`를 같은 폴더에 놓고 `sha256sum -c SHA256SUMS.txt`를 실행합니다. `--build-info`의 `source_sha256`, `vendor_tree_sha256`, target, features, compiler도 확인할 수 있습니다. 실행 파일의 해시는 실제 `/proc/self/exe`를 읽어 계산합니다.

소스 빌드는 Rust와 `x86_64-unknown-linux-musl` target, Python 3가 필요합니다. `python3 scripts/build_release.py`는 오프라인 빌드·테스트를 실행하고 외부 공유 라이브러리와 개발 옵션이 없는지 확인합니다. 배포 빌드에 CPU 전용 최적화 플래그를 넣지 않습니다.

[이전 배포 검증 기록](history_deployment_previous.md)과 [배포판별 과거 검사](distro_validation.md)는 각 문서의 빌드·환경에 한정됩니다.
