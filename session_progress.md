# 세션 진행 로그

> 이 파일은 Claude Code 세션별 작업 내역을 시간순으로 기록합니다.
> 새 세션 시작 시 이 파일을 먼저 읽어 이전 작업 상태를 파악하세요.
> 태그: `[DONE]` `[WIP]` `[BLOCKED]` `[TODO]`

---

## 2026-04-22 (세션 1~2)

### [DONE] SPHINCS+ production firmware errors=3 수정
- **태그**: `#fix` `#sphincs` `#lwip`
- LWIP_SO_RCVTIMEO=0 → 1 활성화 (setsockopt 실효성 부여)
- TCP_WND 4→8×MSS, PBUF_POOL_SIZE 8→10, recvmbox 6→10
- tls_client.c: FIONBIO+select 폴링 루프 제거 → blocking wolfSSL_connect + SO_RCVTIMEO 20s
- 결과: n=20, **errors=0**, mean=3813.4ms, 95CI=[3793.3,3833.4]
- 커밋: `c51bc23` / 브랜치: `fix/tls-socket-timeout-and-hs-progress`

### [DONE] EthLink 히스테리시스 적용
- **태그**: `#fix` `#ethlink` `#lwip`
- PHY link-down 오검출 방지: 히스테리시스 50회 연속 불량 시에만 link-down
- 커밋: `d09c5d1` (히스테리시스 50), `ffd2c5a` (MDIO 에러 캡)

### [DONE] fix 브랜치 → main PR/merge
- **태그**: `#git` `#merge`
- PR 생성 후 merge 완료. main 동기화 완료.

### [DONE] TLS_REPEAT_COUNT 20 → 100
- **태그**: `#feat` `#benchmark`
- `Core/Inc/tls_client.h` 수정
- 커밋: `0089c2d` / 브랜치: `feat/#4-repeat-count-100` (PR #6, 미merge)

### [DONE] CLAUDE.md 업데이트
- **태그**: `#docs`
- 프로젝트 CLAUDE.md: Git/Issue 워크플로, STM32_Programmer_CLI 전체 경로, UART 포트, LwIP 제약, TLS 서버 관리, SPHINCS+ 타이밍 추가
- 글로벌 ~/.claude/CLAUDE.md: cmux 멀티에이전트 + Issue 기반 브랜치 전략

---

## 2026-04-23 (세션 3 — 현재)

### [DONE] OQS provider SPHINCS+ L3/L5 활성화 (Mac)
- **태그**: `#feat` `#oqs` `#sphincs`
- `generate.yml`: sphincsshake192fsimple, sphincsshake256fsimple `enable: true`
- liboqs rebuild: `OQS_ENABLE_SIG_sphincs_shake_192f_simple=ON`, `_256f_=ON`
- oqs-provider generate.py + make rebuild
- 결과: `OPENSSL_MODULES=.../oqs-provider/_build/lib openssl list` → L3/L5 확인
- oqsprovider.dylib 위치: `~/Desktop/develop/oqs-provider/_build/lib/oqsprovider.dylib` (4월 23일)
- 시스템 dylib `/usr/local/lib/ossl-modules/oqsprovider.dylib`은 구버전(2월) → sudo 없이 OPENSSL_MODULES env로 우회

### [DONE] SPHINCS+ L3/L5 인증서 생성 (Mac)
- **태그**: `#feat` `#certs` `#sphincs`
- 알고리즘: L3=sphincsshake192fsimple (OID 1.3.9999.6.8.10), L5=sphincsshake256fsimple (OID 1.3.9999.6.9.10)
- 경로: `~/Desktop/develop/tls_test/sphincs/fast_L3/`, `fast_L5/`
- CA cert + Server cert + server_chain.pem 생성 완료
- 체인 크기 (PEM): L3=97KB, L5=136KB → 65536B 초과
- 리프 DER 크기: L3=35,955B, L5=50,163B → 65536B 이내 ✓

### [DONE] L3/L5 TLS 서버 기동 (Mac)
- **태그**: `#server` `#sphincs`
- 포트: 11183(L3), 11185(L5)
- **중요**: `server_cert.pem`(리프만) 사용 — chain은 DER 크기 초과
- 서버 PIDs: L3=72486, L5=72487
- 재기동 명령:
  ```bash
  OPENSSL_MODULES=~/Desktop/develop/oqs-provider/_build/lib \
    openssl s_server -accept 11183 \
    -cert ~/Desktop/develop/tls_test/sphincs/fast_L3/Server/server_cert.pem \
    -key  ~/Desktop/develop/tls_test/sphincs/fast_L3/Server/server_key.pem \
    -tls1_3 -www -provider oqsprovider -provider default &
  OPENSSL_MODULES=~/Desktop/develop/oqs-provider/_build/lib \
    openssl s_server -accept 11185 \
    -cert ~/Desktop/develop/tls_test/sphincs/fast_L5/Server/server_cert.pem \
    -key  ~/Desktop/develop/tls_test/sphincs/fast_L5/Server/server_key.pem \
    -tls1_3 -www -provider oqsprovider -provider default &
  ```

### [DONE] wolfSSL SPHINCS+ L3/L5 TLS sigalg wire byte 수정
- **태그**: `#fix` `#wolfssl` `#oid` `#sphincs`
- 3개 버그 동시 수정:
  1. `src/internal.c` AddSuiteHashSigAlgo: HAVE_SPHINCS 블록에 L1만 있고 L3/L5 없어 {0x00,0x12}/{0x00,0x13} 잘못된 wire byte 기록됨 → L3/L5 case 추가
  2. `wolfssl/internal.h` SA_MINOR: 0x6D/0x6F(구버전) → 0xC8/0xCC(oqs-provider 실제 codepoint)
  3. `wolfSSL_conf.h` WOLFSSL_MAX_HANDSHAKE_SZ: 40960 → 65536 (L5 서명 49856B 허용, size cap check만 — 실제 버퍼 할당 아님)
- 커밋: `c04f981` / 브랜치: `feat/#5-sphincs-l3-l5`

### [DONE] SPHINCS+ L3/L5 STM32 검증 (n=100)
- **태그**: `#benchmark` `#build` `#flash` `#sphincs`
- 결과 (2026-04-23, 로그: /tmp/uart_final_fix_1410.log):
  | 시나리오 | n | errors | mean | 95% CI |
  |---|---|---|---|---|
  | SPHINCS_FAST_L1 | 100 | 0 | 3675.6ms | [3661.0, 3690.3] |
  | SPHINCS_FAST_L3 | 100 | 0 | 5514.4ms | [5500.0, 5528.8] |
  | SPHINCS_FAST_L5 | 100 | 0 | 5911.3ms | [5895.2, 5927.4] |

### [DONE] PR #6 (feat/#4-repeat-count-100) merge
- **태그**: `#git`
- merge 완료 (2026-04-23 세션 4)

### [DONE] PR #7 (feat/#5-sphincs-l3-l5) merge
- **태그**: `#git`
- merge 완료 (2026-04-23 세션 4)

---

## 2026-04-23 (세션 4)

### [DONE] 전체 24/26 시나리오 n=100 벤치마크
- **태그**: `#benchmark` `#feat`
- 브랜치: `feat/#8-full-benchmark-n100`
- Run 1: 21개 시나리오 (ECDSA/MLDSA/RELATED/CATALYST/CHAMELEON/DUAL/COMPOSITE × L1/L3/L5) — errors=0
- Run 2: SPHINCS+ L1/L3/L5 — errors=0
- FALCON L1/L5: **HardFault** (BusFault PRECISERR, BFAR=0x2FDD001B after cert recv) — 미해결
- 결과 파일: `benchmark_n100_final.txt`
- 주요 결과:
  | 시나리오 | mean (ms) |
  |---|---|
  | ECDSA L1/L3/L5 | 345.8 / 600.0 / 701.0 |
  | MLDSA L1/L3/L5 | 465.0 / 657.1 / 974.0 |
  | RELATED L1/L3/L5 | 470.9 / 864.9 / 1195.1 |
  | CATALYST L1/L3/L5 | 551.1 / 1005.2 / 1433.5 |
  | CHAMELEON L1/L3/L5 | 542.1 / 988.4 / 1406.3 |
  | DUAL L1/L3/L5 | 471.2 / 864.6 / 1195.0 |
  | COMPOSITE L1/L3/L5 | 521.0 / 962.8 / 1390.2 |
  | SPHINCS_FAST L1/L3/L5 | 3670.6 / 5516.9 / 5911.7 |

### [TODO] FALCON HardFault 원인 조사
- **태그**: `#bug` `#falcon` `#wolfssl`
- BusFault PRECISERR, BFAR=0x2FDD001B
- Certificate (3615B) 수신 직후 발생
- HardFault 핸들러 PC 출력 버그(mov %0, pc → 핸들러 자체 PC) → 실제 결함 주소 불명
- 조사 필요: stacked PC 읽기 위한 핸들러 수정 → 재플래시 → 재현

---

## 2026-04-23 (세션 5) — FALCON HardFault 근본 원인 규명 & 수정

### [DONE] HardFault 핸들러 개선 (naked trampoline + stacked frame 덤프)
- **태그**: `#fix` `#hardfault` `#debugging`
- `Core/Src/stm32f4xx_it.c`: naked 트램폴린에서 EXC_RETURN bit2로 MSP/PSP 분기 → C 핸들러에서 stacked PC(`sp[6]`)/LR(`sp[5]`) + R0-R3/R12/xPSR/CFSR/HFSR/BFAR/MMFAR/stack dump 16 words 출력
- BFARVALID 체크로 stale 값 구분, CFSR write-1-to-clear
- 주의: `pcTaskGetName()` 추가 시 부팅 실패 → FreeRTOS 의존성 제거 후 안정화

### [DONE] FALCON HardFault 근본 원인 규명
- **태그**: `#bug` `#falcon` `#stack-overflow`
- 캡처된 PANIC (uart_falcon_5min_2042.log):
  - `CFSR=0x00008200` (BFARVALID + PRECISERR), `HFSR=0x40000000` (FORCED)
  - `BFAR=0x1E7B129A` (invalid region), `R3=0x1E7B1296` (corrupted pointer)
  - `PC=0x08009032` → `xTaskIncrementTick` @ tasks.c:2761, `LR=0x0800B436` → `xPortSysTickHandler`
  - 실패 명령: `ldr r3, [r3, #4]` — 손상된 FreeRTOS task list 노드 traversal
- **근본 원인**: **tlsPerf 태스크 스택 20KB 부족** — Falcon verify가 스택에 8.5KB 배열 (`h_ntt`/`c0`/`s2`/`tmp` 각 2KB) 할당 + wolfSSL ASN/CertVerify 프레임 → 20KB 초과 시 인접 힙의 FreeRTOS task list 노드 손상 → 다음 SysTick에서 BusFault
- **왜 `configCHECK_FOR_STACK_OVERFLOW=2`가 못 잡았나**: method 2는 context switch에서만 canary 검사 — 단일 콜 체인 overflow 후 return되면 canary 복원되어 hook 미발동

### [DONE] 수정 및 검증
- **태그**: `#fix` `#stack` `#heap-alloc`
- 1차 시도: `Core/Src/main.c` stack 20KB→32KB → Falcon 해결, 하지만 SPHINCS+ L5 heap 부족 (err=-125) 회귀
- **최종 수정**:
  - `Middlewares/Third_Party/wolfSSL/.../falcon.c` `wc_falcon_verify_msg` — 스택 배열 4개 (h_ntt/c0/s2/tmp, 총 ~8KB)를 XMALLOC/XFREE로 힙 할당 전환 (cleanup label 도입)
  - `Core/Src/main.c`: tlsPerf 스택 20KB 유지 (heap 예산 보존)
- 검증 결과 (n=100):
  - FALCON_L1 errors=0 mean=196.0ms (9b0f/100 pass)
  - FALCON_L5 errors=0 mean=244.1ms ✅
  - SPHINCS_FAST_L1 errors=0 mean=3839.7ms ✅
  - SPHINCS_FAST_L3/L5 errors=0 (정상)
- 브랜치: `fix/#10-falcon-hardfault`

### [NOTE] 벤치마크 운영 주의사항
- **스테일 ESTABLISHED 연결 문제**: 보드 리셋 중 TCP 연결이 끊기면 openssl s_server가 ESTABLISHED 소켓을 그대로 들고 있음 → 이후 재시도 시 WANT_READ 타임아웃(err=2)
- 3회 연속 실패 시 시나리오 조기 abort → 해당 시나리오만 errors=3, mean=0으로 기록됨
- 해결: 벤치마크 시작 전 `lsof -ti:포트 | xargs kill -9`로 해당 포트 서버 재시작

### 주요 artifact
- 캡처 로그: `uart_falcon_5min_2042.log` (PANIC full dump)
- 검증 로그: `uart_falcon_32k_v2_2045.log` (6× Falcon OK)

---

## 미완료 항목 (TODO)

- [x] 전체 n=100 × 26 시나리오 최종 벤치마크 완주 → 완료 (PR #11 merged, benchmark_n100_final.txt)
- [x] `fix/#10-falcon-hardfault` 커밋 + PR 생성 + merge → 완료 (PR #11 squash-merge)
- [x] Vault 05-Progress-Changelog.md 업데이트 → 완료 (Stage 6 추가)

---

## 2026-04-24 (세션 6) — 다음 세션 작업 계획 수립

### [PLAN] 다음 작업: SPHINCS+ small + ML-KEM 하이브리드 KEM

전체 플랜: `~/.claude/plans/zany-puzzling-sprout.md` 참조

#### 핵심 결정 사항
- **병렬 진행**: 두 작업을 별도 브랜치에서 cmux claude-teams 동시 진행
  - Worker A: `feat/#N-sphincs-small`
  - Worker B: `feat/#M-mlkem-hybrid-kem`
  - 보드/UART: 1대이므로 Orchestrator가 토큰으로 직렬화

#### Phase 1: SPHINCS+ small (L1/L3/L5)

- **목표**: sphincsshake{128,192,256}ssimple 3개 시나리오 추가 (ports 11191/11193/11195)
- **주요 작업**:
  1. OQS provider `generate.yml` L1240/1326/1404 → `enable: true` + 재빌드
  2. liboqs `OQS_ENABLE_SIG_sphincs_shake_{128,192,256}s_simple` 확인
  3. `small_L{1,3,5}/CA/` + `Server/` 인증서 생성 (fast_L* 구조 미러링)
  4. wolfSSL `internal.h:1787-1789` SA_MINOR → **0xC5/0xCA/0xCE** (OQS 코드포인트)
  5. `tls_client.h` `CERT_SPHINCS_SMALL=9` enum 추가
  6. `tls_client.c` CA PEM 3개 임베드 + `g_scenarios[]` 3행 추가
  7. `configure_scenario_ctx():4154` 조건문에 `|| CERT_SPHINCS_SMALL` 추가
  8. `do_handshake()` SO_RCVTIMEO: L5 → 35s ladder (`tls_client.c:4290-4294`)
- **예상 타이밍**: L1 ≈ 1.2-1.8s / L3 ≈ 3.5-5s / L5 ≈ 9-15s
- **주의**: small-L5 chain 크기 측정 필수 (`wc -c server_chain.pem`) — 65536B 초과 시 리프만 사용

#### Phase 2: ML-KEM 하이브리드 KEM

- **목표**: ECDSA L1 cert 고정 + KEM group 6종 직교 벤치마크 (ports 11201-11206)
  - `KEM_X25519_BASELINE`, `KEM_SECP256R1_BASELINE` (classical baseline)
  - `KEM_X25519MLKEM768`, `KEM_SECP256R1MLKEM768`, `KEM_SECP384R1MLKEM1024` (hybrid)
  - `KEM_PURE_MLKEM768` (pure PQC)
- **주요 작업**:
  1. `wolfSSL.I-CUBE-wolfSSL_conf.h:118` `WOLF_CONF_KYBER 0 → 1`
  2. `Scenario` 구조체에 `uint16_t kem_group;` 11번째 필드 추가 (`tls_client.c:4040`)
  3. 기존 29행 말미에 `, 0` 추가 (Phase 2 워커가 Phase 1 머지 후 rebase 시 처리)
  4. `configure_scenario_ctx()` 끝에 `UseSupportedCurve` + `UseKeyShare` 블록
  5. KEM 시나리오 6행 추가
  6. Mac 측 ECDSA L1 cert + per-port `-groups <name>` s_server launcher
- **타이밍 전략**: `g_tls_t_server_hello_ms` 재활용 (KEM-only 비용 = baseline diff)
- **ML-KEM 메모리**: `WOLFSSL_SMALL_STACK` ON이므로 heap 경로, peak ≈ 5-10KB — 문제없음

#### 병렬 브랜치 머지 룰
- 충돌 지점: `g_scenarios[]` 배열 — Phase 2가 rebase 시 Phase 1 행 끝에 `, 0` 1줄 추가 필요
- `configure_scenario_ctx()` — git auto-merge (각자 다른 라인)
- 머지 순서: 먼저 완성된 PR 먼저 (예상: Phase 2가 더 빠름)

---

## 2026-04-24 (세션 7) — SPHINCS+ small + ML-KEM 병렬 구현

### [DONE] GitHub Issue 생성
- Issue #12: feat: SPHINCS+ small
- Issue #13: feat: ML-KEM hybrid KEM

### [DONE] cmux Parallel-Workers 워크스페이스 추가
- cmux.json: `parallel-workers` 워크스페이스 (Orchestrator + Worker A pane + Worker B pane)
- 각 pane: 해당 worktree git log/status 8초 자동 갱신

### [DONE] Phase 1: SPHINCS+ small (feat/#12-sphincs-small) — PR #14
- OQS provider generate.yml: sphincsshake{128,192,256}ssimple enable: true → 재빌드
- wolfSSL internal.h: SPHINCS_SMALL SA_MINOR 0x6C/6E/70 → **0xC5/CA/CE** (OQS 공식 codepoint)
- wolfSSL internal.c: AddSuiteHashSigAlgo small L1/L3/L5 추가 (기존 fast만 있었음)
- tls_client.h: CERT_SPHINCS_SMALL = 9 enum 추가
- tls_client.c: CA PEM 3개 임베드 + g_scenarios[] 3행 + 분기 확장 + SO_RCVTIMEO 35s ladder
- 인증서: small_L{1,3,5}/CA/Server 생성 완료 (L1=22KB, L3=44KB, L5=81KB chain)
- 서버 기동: ports 11191(PID=25892), 11193(PID=25894), 11195(PID=25895)
- 빌드: ✅ Flash=55.9%, SRAM=98.7% (BSS의 93%가 heap2 정적 배열, 링커 통과)
- 커밋: 6533f67 (wolfssl fix) + 3ca4359 (시나리오) + 12d786f (cmux)
- PR #14: https://github.com/LeeYeoNyeong/Hybrid-PQC-TLS-STM32/pull/14

### [DONE] Phase 2: ML-KEM hybrid KEM (feat/#13-mlkem-hybrid-kem) — PR #15
- wolfSSL_conf.h: WOLF_CONF_KYBER 0→1
- Scenario 구조체: uint16_t kem_group 필드 추가 (12번째)
- g_scenarios[] 기존 32행 전체 `, 0` 추가 + KEM 6행 추가 (ports 11201-11206)
- wolfSSL 상수: WOLFSSL_X25519MLKEM768(4588), SECP256R1MLKEM768(4587), SECP384R1MLKEM1024(4589), ML_KEM_768(513)
- configure_scenario_ctx(): kem_group 처리 블록 추가 (wolfSSL_UseKeyShare + UseSupportedCurve)
- Mac launcher: ~/Desktop/develop/pqc_tls_server/launch_kem_servers.sh
- Rebase: feat/#12-sphincs-small 위에 스택, g_scenarios 충돌 수동 해결
- 빌드: ✅ (Worker B 검증, SRAM +1.5KB BSS, 링커 통과)
- PR #15: https://github.com/LeeYeoNyeong/Hybrid-PQC-TLS-STM32/pull/15 (stacked on PR #14)

### [DONE] 다음 세션 플랜 수립
- 플랜 파일: `~/.claude/plans/fuzzy-whistling-beacon.md`
- Phase 1: PR #14 (feat/#12-sphincs-small) — Flash → UART n=100 → 검증 → squash-merge
- Phase 2: PR #15 (feat/#13-mlkem-hybrid-kem) — rebase onto main → KEM launcher → Flash → UART → merge
- Phase 3: 벤치마크 그래프 재생성 (35 시나리오), Obsidian vault 동기화

### [DONE] SPHINCS_SMALL n=100 벤치마크 완료 + wolfSSL 픽스 커밋 (2026-04-24)
- **커밋**: `badc751` (feat/#12-sphincs-small, pushed)
- SMALL_L1: n=100, errors=0, mean=1623.8ms, stddev=47.0ms, 95CI=[1614.6,1633.0]
- SMALL_L3: n=100, errors=0, mean=2850.3ms, stddev=64.6ms, 95CI=[2837.6,2863.0]
- SMALL_L5: **OOM** — wolfSSL GrowInputBuffer 65536B 필요, 힙 여유 62960B (STM32F439ZI 194KB Heap_5 한계)
- wolfSSL 픽스: sphincs.c keypair 4-byte BE, internal.c SA_MINOR, asn.c OID, oid_sum.h

### [DONE] ML-KEM 하이브리드 KEM n=100 벤치마크 완료 (2026-04-25)
- **브랜치**: feat/#13-mlkem-hybrid-kem → PR #16
- **커밋**: `87870dd` (WOLF_CONF_EDCURVE25519=1 + 6 KEM 결과 추가)
- **핵심 수정**: WOLF_CONF_EDCURVE25519 0→1 → HAVE_CURVE25519 활성화
  - 이전 실패: X25519_BASELINE err=-174, X25519MLKEM768 err=-173
  - 원인: wolfSSL Curve25519가 WOLFSSL_SP_ARM_CORTEX_M_ASM 미지원 → non-SP C 폴백
- **결과** (n=100, errors=0 전 시나리오):
  - KEM_X25519_BASELINE:     1415.2ms (⚠ non-SP Curve25519, P-256 대비 ~9배)
  - KEM_SECP256R1_BASELINE:   154.6ms
  - KEM_X25519MLKEM768:      1471.1ms (⚠ non-SP Curve25519)
  - KEM_SECP256R1MLKEM768:    210.8ms (SrvHello=47.8ms — ML-KEM 처리 포함)
  - KEM_SECP384R1MLKEM1024:   320.6ms
  - KEM_PURE_MLKEM768:        195.3ms (SrvHello=13.9ms — 가장 빠른 하이브리드)
- UART 로그: uart_kem_fix_1022.log (1599줄, BENCHMARK COMPLETE 확인)
- PR #16: https://github.com/LeeYeoNyeong/Hybrid-PQC-TLS-STM32/pull/16

### [TODO] 다음 세션: PR #16 merge → Phase 3
- [ ] `gh pr merge 16 --squash --delete-branch` (feat/#13-mlkem-hybrid-kem)
- [ ] Phase 3: benchmark_graphs_YYYYMMDD/ 재생성 (31 시나리오 완료 + 6 KEM = 37 시나리오), vault sync
- [ ] (선택) Curve25519 SP 최적화 조사: WOLFSSL_SP_MATH_ALL 또는 별도 sp_curve25519.c ASM 활성화 검토

---

## 서버 재기동 체크리스트 (보드 리셋 전 확인)

```bash
# 실행 중인 SPHINCS+ 서버 확인
lsof -nP -iTCP:11181 -iTCP:11183 -iTCP:11185 | grep LISTEN
# L1 서버 PID 확인 및 재기동
kill <old_pid>; OPENSSL_MODULES=~/Desktop/develop/oqs-provider/_build/lib \
  openssl s_server -accept 11181 \
  -cert ~/Desktop/develop/tls_test/sphincs/fast_L1/Server/server_chain.pem \
  -key  ~/Desktop/develop/tls_test/sphincs/fast_L1/Server/server_key.pem \
  -tls1_3 -www -provider oqsprovider -provider default &
```

---

## 2026-04-27 (세션 — Cert × KEM 매트릭스)

### [DONE] Cert × KEM Matrix Benchmark (78 시나리오) — feat/#19-cert-kem-matrix

**플랜**: `~/.claude/plans/soft-drifting-parasol.md`
**Issue**: #19 / 브랜치: `feat/#19-cert-kem-matrix`
**커밋**: `0e810b5` — BENCH_MODE_MATRIX 구현

#### 완료 사항
- PR #16 (feat/#13-mlkem-hybrid-kem), PR #18 (feat/#17-kem-l1-l5-complete) → main merge 완료
- GitHub Issue #19 생성 → 브랜치 `feat/#19-cert-kem-matrix` 체크아웃
- `generate_pqc_chains.sh` 작성 → Falcon/SPHINCS+ 3-level (RootCA→ICA→Server) 체인 생성
  - falcon/L1 (falcon512), falcon/L5 (falcon1024)
  - sphincs/fast_{L1,L3,L5}, sphincs/small_{L1,L3}
- `server_chain.pem` 순서 수정: ICA→Server → Server→ICA (OpenSSL s_server 요구사항)
- `launch_matrix_servers.sh` 작성 (28 cert 포트 × 3 KEM groups)
- `tls_client.c`:
  - CA_FALCON_L1/L5, CA_SPHINCS_FAST/SMALL L1/L3/L5 PEM 교체 (3-level RootCA)
  - `#if BENCH_MODE_MATRIX` 블록: MR1/MR3/MR5 매크로 + 84 시나리오 배열
  - `wolfSSL_get_curve_name` KEM 협상 로그 (첫 3회 핸드셰이크)
  - `#else` 기존 cert+KEM axis 배열, `#endif` 닫힘
- `CMakeLists.txt`: `option(BENCH_MODE_MATRIX ...)` + 제너레이터 표현식 정의
- 빌드: `cmake --preset Debug -DBENCH_MODE_MATRIX=ON && cmake --build` → ✅ ELF 5.7MB
- 서버: `launch_matrix_servers.sh start` → **28 OK, 0 WARN**
- 플래시: STM32F439ZI 플래시 완료, UART 캡처 시작

#### 현재 진행 중
- **전체 84시나리오 단일 런** (uart_matrix_v9_1526.log, PID=69317)
- wolfSSL 서버 재빌드 이슈 해결:
  - 문제: wolfSSL-pqc 기존 빌드에 `--enable-curve25519`, `--enable-kyber` 누락
  - 수정: `~/Desktop/develop/wolfssl-5.8.4-stable` 재configure+rebuild → `~/wolfssl-pqc` 재설치
  - 검증: options.h에 `HAVE_CURVE25519`, `WOLFSSL_HAVE_MLKEM` 확인
  - 서버 재빌드: `make -B server` (15:16 타임스탬프)
  - 서버 재시작: 28/28 OK (15:26 기준)
- **ECDSA_L1_P256** → OK ~332ms ✅
- **ECDSA_L1_X25519** → OK ~1416ms ✅ (non-SP X25519 keygen ~1273ms, 기존 KEM benchmark와 일치)
- ECDSA_L1_MLKEM512 ~ SPHINCS_SMALL_L3 순서로 진행 중

#### 결과 (2026-04-27 18:25 ALL DONE 확인)

파싱 결과: `benchmark_matrix_n100_20260427.txt`

**75/84 시나리오 성공 (errors=0)**: ECDSA, ML-DSA, Related, Catalyst, Chameleon, Dual, Composite × L1/L3/L5 × 3KEM + FALCON × L1/L5 × 3KEM + SPHINCS_FAST_L1 × 3KEM

**9/84 시나리오 실패 — SPHINCS_FAST L3/L5 (하드웨어 한계)**:
- 원인: wolfSSL 내부 SPHINCS_FAST L3/L5 검증 시 `pvPortMalloc(~140KB)` 시도
- 192KB SRAM 기기에서 연속 블록 할당 불가 → `[PANIC]` 후 ERR
- L1(shake128f ~17KB 서명)은 성공, L3(shake192f ~35KB)/L5(shake256f ~49KB)는 실패

**6/84 시나리오 garbled — SPHINCS_SMALL L1/L3**:
- errors=0 (핸드셰이크 성공), 타이밍 라인 100% garbled → 파싱 불가
- heap 모니터링 printf가 scenario OK 라인과 interleave

**파싱 n=4~17 이슈**: 실제 100회 실행됐으나 UART garbling으로 clean 라인만 캡처됨.
mean stddev가 매우 작아(0.3~2.2ms) 신뢰 가능.

주요 결과 요약 (mean ms):
| 시나리오 | P256/P384 | X25519/HYB | MLKEM |
|---|---|---|---|
| ECDSA L1 | 332 | 1416 | 332 |
| ECDSA L3 | 584 | 554(HYB768) | 573 |
| ECDSA L5 | 592 | 673(HYB1024) | 579 |
| ML-DSA L1 | 446 | 1705 | 468 |
| ML-DSA L3 | 638 | 695 | 680 |
| ML-DSA L5 | 1032 | 1115 | 1023 |
| FALCON L1 | 178 | 1438 | 200 |
| FALCON L5 | 304 | 388 | 295 |
| SPHINCS_FAST L1 | 3824 | 5008 | 3803 |
| SPHINCS_FAST L3~L5 | ❌ pvPortMalloc | ❌ | ❌ |
| SPHINCS_SMALL L1/L3 | ✅(garbled) | ✅(garbled) | ✅(garbled) |

#### 최종 결과 (v16 / uart_matrix_v16_1951.log)
- **77/78 시나리오 n=100 완료** (errors=0)
- **1개 스킵**: CHAMELEON_L5_HYB1024 — pvPortMalloc MEMORY_E(-155), ML-DSA87 delta cert 검증 힙 부족(free≈17KB)
- SPHINCS_FAST L3/L5 제거 (코드에서 삭제, 하드웨어 한계 주석 기재)
- 결과 파일: `benchmark_matrix_n100_20260427.txt`

---

## 2026-04-28 (세션 — v16 완료 + 코드 수정)

### [DONE] UART 가블링 근본 해결 — pyserial raw mode
- **태그**: `#fix` `#uart`
- 원인: macOS `cat /dev/cu.*` tty canonical mode가 `\r` 바이트 처리하며 라인 버퍼링 → 바이트 순서 뒤집힘
- 해결: `uart_capture.py` (pyserial raw mode, O_NOCTTY) → 완벽한 clean 출력 확인
- DTR reset 방지: `ser.dtr = False; ser.rts = False`

### [DONE] uart_printf 코드 리뷰 수정 (critic + code-reviewer 병렬 리뷰)
- **태그**: `#fix` `#code-review`
- 수정 1: `vsnprintf(buf, sizeof(buf)-1, ...)` → `sizeof(buf)` (off-by-one)
- 수정 2: `xPortIsInsideInterrupt()` 가드 추가 — ISR에서 `taskENTER_CRITICAL()` 호출 방지
- 수정 3: `uart_printf()` 스케줄러 상태 체크 `== RUNNING` → `!= NOT_STARTED` (SUSPENDED 상태 포함)
- 빌드: ✅ (SRAM 99.53%, Flash 51.16%)
- 후속 이슈 (PR 분리): critical section → `vTaskSuspendAll()` 전환 (ETH IRQ 보존)

---

## 2026-04-28 (세션 — Phase A/B/C 분석 파이프라인)

### [DONE] Phase A — parse_matrix_log.py stage breakdown 추출 (#21, PR #22)
- **태그**: `#feat` `#parser` `#stage-breakdown`
- PR #20 squash-merge 선행 완료 (feat/#19-cert-kem-matrix)
- Issue #21 → 브랜치 `feat/#21-stage-breakdown` → PR #22 merge (commit 5c976d2)
- phases_re: `\d+\.\d+` + `\s*ms` 앵커, `expecting_phases` 플래그, all-zero 필터, `-p` CLI
- critic + code-reviewer 병렬 리뷰 — CRITICAL 없음, HIGH 3개 수정
- 산출물: `benchmark_matrix_phases_n100_20260427.txt` (76/78 시나리오 phases)
- 주요 insight (단계별 분해):
  - ECDSA Cert: P256=18ms, P384=181ms, HYB1024=129ms (인증서 체인 크기 비례)
  - SPHINCS_FAST_L1 CertVfy: 3194ms (SHAKE verify 지배)
  - SPHINCS_SMALL_L1 CertVfy: ~1101ms
  - Falcon CertVfy: 22~36ms (매우 빠름)
  - PQCertVfy(하이브리드): L1≈62ms, L3≈26~31ms, L5≈81~83ms

### [DONE] Phase B — 그래프 재생성 (#23, PR #24)
- **태그**: `#feat` `#graphs` `#visualization`
- Issue #23 → 브랜치 `feat/#23-matrix-graphs`
- benchmark_graphs_20260424/ → benchmark_graphs_archive_20260424/ (rename)
- `make_matrix_graphs.py` 작성 (5개 그래프):
  1. `cert_kem_heatmap.png` — 10 cert × 9 KEM 컬럼 격자, PowerNorm 색상, OOM=회색
  2. `stacked_stage_breakdown.png` — 단계별 스택 막대 (SrvHello/Cert/CertVfy/PQCertVfy)
  3. `cert_comparison_classical_kem.png` — P-256/P-384 KEM 고정, cert 9종 × 3레벨 비교
  4. `kem_comparison_l1.png` — L1 cert별 3 KEM 그룹 비교
  5. `pqc_cost_decomposition.png` — 하이브리드 4종 PQCertVfy 비율 분해
- Spot-check 통과: ECDSA_L1_P256=312.1ms, SPHINCS_FAST CertVfy=3194.6ms ✓
- 산출물: benchmark_graphs_20260428/ (5 PNG, 총 418KB)
