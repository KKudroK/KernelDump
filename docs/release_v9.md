# v9 릴리즈 파일

[v1.2.1](https://github.com/KKudroK/KernelDump/releases/tag/v1.2.1)은 팀의 수정 사항을 합친 정적 Linux x86-64 실행 파일이다. 프로그램 내부 버전은 0.1.1, 수집 정책은 `kernel-focused-v9`다. 태그 번호와 내부 버전은 서로 다르다.

- `kerneldump-v1.2.1-linux-x86_64.tar.gz`: 실행 파일·빌드 출처·사용법·라이선스·의존성 고지·내부 체크섬
- `SHA256SUMS.txt`: 압축 파일 체크섬

실행 파일 SHA-256: `fff51010cebe3f66de53dca80deef676eaa3ed2e5aef9c86d843a53b56181ef4`

압축 파일 SHA-256: `0d8977bd7f94f5a0f2144a04d90ca95a6aee197c01f49689e2e792041f30593d`

```sh
sha256sum -c SHA256SUMS.txt
mkdir kerneldump-v1.2.1
tar -xzf kerneldump-v1.2.1-linux-x86_64.tar.gz -C kerneldump-v1.2.1
cd kerneldump-v1.2.1
sha256sum -c SHA256SUMS.txt
```

첫 검사는 내려받은 압축 파일, 두 번째 검사는 압축 안의 파일을 확인한다. 실행 파일에 담긴 소스 해시와 `manifest.json`을 함께 확인할 수 있다. 생성된 `release/`와 `release_assets/`는 Git에 넣지 않고 Release 첨부 파일로 제공한다.

v1.2.1은 원장 한 줄의 허용 크기를 쓰기와 검증 양쪽에서 맞추고, 열린 파일·소켓의 연결을 다시 확인하는 절차와 v9 완료 조건 검사를 보강했다. 의존 파일의 원본 바이트와 체크섬을 맞추고 Linux 7.0 파일 캐시 배치도 처리한다. [수정 내역](fixes_20261104.md), [7.0 검증과 한계](kernel_7_0_0_38_validation.md)를 따른다.

Rust 1.93.0의 정적 musl 빌드에서 검사 75개를 통과했다. 같은 실행 파일로 AWS AL2023 6.18.56에서 Pod UID 지정 수집과 `verify`도 통과했다. 준비 검사나 단일 수집 성공은 모든 커널의 호환성·운영 성능을 보장하지 않는다. 이전 [원본 대비 비용](original_comparison.md)은 이전 빌드의 실측이다.

이전 [v1.2.0](https://github.com/KKudroK/KernelDump/releases/tag/v1.2.0)의 실행 파일 해시는 `b16a6ad7419f3e6bc2e7871a2362a9e849af1a3129b72458fb1a6018b4fa2fe0`이고 압축 파일 해시는 `08df4af06e5d54196c726e460ee620420cc8b42b63e522185021fbef95a2c846`이다. 이전 첨부 파일은 그대로 유지한다.
