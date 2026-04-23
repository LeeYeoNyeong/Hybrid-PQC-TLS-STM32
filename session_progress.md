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

- [ ] 전체 n=100 × 26 시나리오 최종 벤치마크 완주 (현재 실행 중)
- [ ] `benchmark_n100_final.txt` 갱신 + `project_goals.md` 최종 표 업데이트
- [ ] `fix/#10-falcon-hardfault` 커밋 + PR 생성 + merge
- [ ] Vault 05-Progress-Changelog.md 업데이트

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
