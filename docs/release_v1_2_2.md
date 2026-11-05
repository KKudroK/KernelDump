# v1.2.2 릴리즈 파일

[v1.2.2](https://github.com/KKudroK/KernelDump/releases/tag/v1.2.2)는 선택한 Pod의 공유 memfd가 FD를 닫았어도 현재 메모리 매핑에서 찾는 보완을 포함한다. 프로그램 내부 버전은 0.1.1, 수집 정책은 `kernel-focused-v9`다.

- `kerneldump-v1.2.2-linux-x86_64.tar.gz`: 실행 파일·빌드 출처·사용법·라이선스·의존성 고지·내부 체크섬
- `SHA256SUMS.txt`: 압축 파일 체크섬

실행 파일 SHA-256: `0c25851d9b7e6a9351f62dd1d2ed63422eeba38d2930751df5623bde324522f2`

압축 파일 SHA-256: `b41a3c4d2601955a1b4a2f326cee92bb4929a34702c67271fff4ddaeb09fa248`

```sh
sha256sum -c SHA256SUMS.txt
mkdir kerneldump-v1.2.2
tar -xzf kerneldump-v1.2.2-linux-x86_64.tar.gz -C kerneldump-v1.2.2
cd kerneldump-v1.2.2
sha256sum -c SHA256SUMS.txt
```

memfd 탐색은 기존 소켓 단계 뒤의 캐시 예산 안에서 수행한다. 동일 주소 공간의 proc maps 읽기 중복을 줄이고 512KiB 한도와 기존 4MiB·100ms 예산에 포함한다. 파일 위치·inode·VMA와 task/mm·PID·시작값을 대조하며, 공유와 사유 매핑을 구분한다. 작업 큐의 총 128개 한도를 유지한다. [팀의 수정·VM 검증과 한계](scenario2_memfd_20261104.md)를 따른다.

새 작업 폴더에서 드러난 generic-array의 두 의존 파일은 공식 crate의 원래 바이트로 복원했다. crate 압축 파일 해시와 파일별 기존 체크섬을 확인했으며 체크섬 기록 자체를 바꾸지 않았다.

Rust 1.93.0의 정적 musl 빌드에서 검사 82개를 통과했다. 정적 ELF·개발 옵션 제외·내장 소스 해시·실행 파일 해시를 확인했다. 같은 바이너리로 AWS AL2023 6.18.56에서 준비 검사를 통과했고 이전 실행 파일은 버전 폴더에 유지한다. 새 바이너리로 AWS에서 새 덤프를 수집한 결과는 아니며, 팀 문서의 로컬 VM 검증과 구분한다.

생성된 release와 release_assets 폴더는 Git 대신 Release 첨부 파일로 제공한다. manifest.json에서 빌드 소스·의존 파일 묶음·실행 파일 해시를 확인할 수 있다. 수집은 비원자적이며 모든 커널·과거 참조·중요 페이지의 무누락을 보장하지 않는다.

이전 [v1.2.1 파일과 검증](release_v9.md)은 당시 기록으로 유지한다.
