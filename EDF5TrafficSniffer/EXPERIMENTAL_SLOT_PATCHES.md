# Inventario de patches de slots experimentais

Atualizado em: 2026-08-27

Executavel suportado: `EDF5.exe` SHA-256
`3512D2A2E61D532C5D12DC0C5FD1AC61F6743E13349AE21301BB8449DD4BAE5F`

Build de teste: `0.6.13` / `edf5mp-0.6.13-result-item-fold-win64`

Este arquivo separa limites comprovados de comparacoes que apenas parecem
capacidade. Um RVA nesta lista nao significa automaticamente "jogadores".

## Estados

- `PROVEN`: relacionado ao roster por dumps/call flow e mantido ativo.
- `EXP-ENABLED`: grupo coerente `capacity < 4` + `reserve(4)`, alterado em
  conjunto para 8, mas o sistema proprietario ainda nao foi identificado.
- `HOLD`: nao alterado; comparacao de tipo/estado ou fluxo ambiguo.
- `MANUAL-PASS` / `MANUAL-FAIL`: preencher somente depois de teste no jogo.

O lote experimental pode ser desligado sem remover os patches comprovados:

```ini
[MorePlayers]
ExperimentalReservePatches=false
```

## Baseline comprovado: 22 operandos

| Grupo | RVAs | Estado |
|---|---|---|
| roster primario | `0x44894B`, `0x448961` | PROVEN |
| roster secundario | `0x432AF9`, `0x432B14`, `0x432B2C`, `0x436996`, `0x4369B2`, `0x4369DB`, `0x436AAC` | PROVEN |
| roster terciario | `0x419789`, `0x4197A4`, `0x4197BC`, `0x41BB36`, `0x41BB52`, `0x41BB76`, `0x41BC0D` | PROVEN |
| caixas da sala | `0x5A59FC`, `0x5A5A14`, `0x5A7261`, `0x5A726D`, `0x5A7281`, `0x5A72DC` | PROVEN |

## Os 35 anchors antes nao classificados

Vinte e quatro formam grupos de reserva coerentes. Cada linha `EXP-ENABLED`
possui dois operandos: o anchor de comparacao e o argumento de `reserve(4)`.
Isso totaliza 48 modificacoes experimentais. Os outros onze permanecem
intactos.

| # | Anchor | Segundo operando | Classificacao | Teste manual | Observacao |
|---:|---:|---:|---|---|---|
| 1 | `0x005B6C1` | - | HOLD | nao testado | comparacoes de campos/estado; nao e padrao de reserva |
| 2 | `0x00D2238` | - | HOLD | nao testado | seleciona constantes SIMD conforme estado 4 |
| 3 | `0x00D25B6` | - | HOLD | nao testado | seleciona constantes SIMD conforme estado 4 |
| 4 | `0x014958D` | `0x0149594` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 5 | `0x01CDCF2` | `0x01CDCF9` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 6 | `0x01CE773` | `0x01CE77A` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 7 | `0x01D8176` | `0x01D817D` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 8 | `0x01D95AD` | `0x01D95B4` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 9 | `0x01F7D70` | `0x01F7D77` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 10 | `0x01FBF2A` | `0x01FBF31` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 11 | `0x01FC508` | `0x01FC50F` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 12 | `0x025D408` | `0x025D40F` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 13 | `0x0263925` | `0x026392C` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 14 | `0x02769A2` | `0x02769A9` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 15 | `0x0282612` | `0x0282619` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 16 | `0x029CBA2` | `0x029CBA9` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 17 | `0x02A27A5` | `0x02A27AC` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 18 | `0x02A6F6F` | `0x02A6F76` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 19 | `0x02B0242` | `0x02B0249` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 20 | `0x02B837D` | `0x02B8384` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 21 | `0x02BB10D` | `0x02BB114` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 22 | `0x02BD3CF` | - | HOLD | nao testado | checa capacidade e tamanho em fluxo existente; nao reserva |
| 23 | `0x02C4B67` | `0x02C4B6E` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 24 | `0x02D17F3` | `0x02D17FA` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 25 | `0x034EAA0` | `0x034EAA7` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 26 | `0x035037A` | `0x0350381` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 27 | `0x047A4CF` | `0x047A4D6` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 28 | `0x04AECFE` | `0x04AED05` | EXP-ENABLED | nao testado | comparacao + `reserve(4)` |
| 29 | `0x0971940` | - | HOLD | nao testado | dispatch de objeto/tipo igual a 4 |
| 30 | `0x09722C7` | - | HOLD | nao testado | filtro de objeto/tipo igual a 4 |
| 31 | `0x0C3B97C` | - | HOLD | nao testado | switch de tipo; escreve id `0x8A` |
| 32 | `0x0C3B9FA` | - | HOLD | nao testado | switch de tipo junto a ids `0x45`/`0x31` |
| 33 | `0x0C3BA2D` | - | HOLD | nao testado | switch de tipo junto a ids `0x31`/`0x43` |
| 34 | `0x0C3BC1A` | - | HOLD | nao testado | switch de tipo; escreve id `0xB9` |
| 35 | `0x0C3BC76` | - | HOLD | nao testado | switch de tipo; escreve id `0xBA` |

## Registro de testes

| Data | Build | Configuracao | Resultado | Reports | Notas |
|---|---|---|---|---|---|
| 2026-08-26 | 0.4.9 | `PreallocatedRosterSlots=8`; lote experimental ausente | partida solo abriu, entrou em mission e encerrou limpa | `Reports/single.zip` | valida somente o baseline de 22 operandos; nao testou estas 35 modificacoes |
| pendente | 0.5.0 | `ExperimentalReservePatches=true` | nao testado | - | primeiro teste do lote 24/48 |
| pendente | 0.5.1 | `MaxPlayers=8`; `PreallocatedRosterSlots=8`; lote experimental ativo | nao testado | - | primeiro teste dos caminhos dinamicos de missao para jogadores 5-8 e do lote 24/48 |
| pendente | 0.6.9 | `MaxPlayers=5`; `PreallocatedRosterSlots=8`; lote experimental ativo | nao testado | - | novo filtro comprovado `MissionSync_Res` 4->MaxPlayers; separado dos 35 anchors experimentais |
| pendente | 0.6.10 | mesma capacidade; rollback do parser extra, sidecar de classe e retorno efetivo da vitoria | nao testado | - | P4 comeca em `state+0x24570` e sobrepoe `+0x2459C/+0x245A0`; restaura toda a faixa extra e preserva somente o count legitimo do resultado |
| pendente | 0.6.11 | mesma capacidade; matriz de replicacao P0-P7 e auditoria de identidade unica | nao testado | - | nenhum limite de quatro encontrado em `0x45EAD0/0x432D20/0x435670`; detecta UserImpl duplicado e ausencia de host em cada cliente sem capturar IDs/payload |
| pendente | 0.6.12 | mesma capacidade; auditoria da tabela real de recepcao `+0xD0/+0xE0` | nao testado | - | callback `0x451B90 -> 0x4336F0` usa count dinamico e stride `0x10`; detecta rota P0 ausente ou P0/P4 duplicada antes do parser sem capturar IDs/payload |
| pendente | 0.6.13 | mesma capacidade; filtro dinamico e fold seguro de Items extras do resultado | nao testado | - | `0x430F23` passa a seguir MaxPlayers; hook em `0x132BB0` soma P4-P7 nos quatro acumuladores que terminam antes de rewards em `+0x2459C` |
| pendente | 0.6.14 | mesma capacidade; origem do nick e checkpoint de Items antes dos rewards | nao testado | - | cruza participante/UserImpl/PlayerInfo/chat por tokens privados; assinaturas provam ResolveResult com quatro totais agregados e ApplyResult com vetor dinamico |
| pendente | 0.6.15 | mesma capacidade; identidade da rota de transporte `UserImpl+0xC8` | nao testado | - | audita alocador dinamico, registro/remocao e mapeamento exato rota -> participante; detecta rota do host ausente, colisao P0/P4 e indice fora do slot sem coletar endpoints |
| substituida antes do teste | 0.6.16 | primeira auditoria do fan-out do serializador | nao testado | - | hipotese de elemento `SharedProperty` 16 bytes estava errada; reverse de `0x45ED80/0x432E00` provou descritor de rota com stride 8 |
| pendente | 0.6.17 | mesma capacidade; fan-out exato por descritor de rota | nao testado | - | cruza `UserImpl+0xC4/+0xC8 -> descritor+4 -> manager+0xD0` e exige a mascara exata dos remotos sem coletar rota bruta, IDs, endpoints ou payloads |
| pendente | 0.6.18 | mesma capacidade; matriz completa de Items do resultado | nao testado | - | registra apenas presenca P0-P7 em checkpoints/ResolveResult/ApplyResult, separada do fold de P4-P7; nao coleta valores de armas, rewards ou payloads |
| pendente | 0.6.19 | mesma capacidade; restauracao defensiva do contador local de rewards | nao testado | - | usa a colecao local real 1..2 para reparar `state+0x2459C` somente se invalido antes de ApplyResult em vitoria P4+; nao le conteudo de armas/rewards |
| 2026-08-31 | 0.6.52 | cinco jogadores reais; `MaxPlayers=8`, multiplicador de inimigos desligado | duas fases com controles, spawns, rewards e retornos completos nas cinco maquinas | `Reports/server.zip`; `Reports/client 01.zip`; `Reports/client 2.zip`; `Reports/client 3.zip`; `Reports/client 4.zip` | valida em conjunto rollback/sidecar P4, classe, visual, fan-out de quatro remotos, Items `0x1f`, ApplyResult concluido e cancelamento nativo; incoming por participante e nickname de missao permanecem pendentes |
| pendente | 0.5.2 | mesma capacidade; auditoria de indice/P2P ativa | nao testado | - | registra callers e indices extras sem ampliar candidatos ambiguos |
| 2026-08-27 | 0.5.3 | cinco jogadores reais; mesma capacidade | entrou no gameplay sem crash, mas com lag/desync severo e controle incorreto | reports de servidor e tres clientes em `Reports` | jogador de indice 4 foi reciclado para a fonte 0 nos quatro reports |
| pendente | 0.5.4 | mesma capacidade; auditoria das colecoes UserImpl e mensagens logicas | nao testado | - | usa fonte 4 somente quando ela existe e preserva modulo quatro como fallback |
| 2026-08-27 | 0.5.4 | dois jogadores reais; mesma capacidade | fase completou, transporte limpo | `Reports/Server 2 players.zip`; `Reports/Client 2 players.zip` | colecao completa com 2 UserImpl distintos; subconjunto local com 1; revelou que +0x190 nao e posicao global |
| pendente | 0.5.5 | mesma capacidade; ordem UserImpl e resolucao de fonte ativas | nao testado | - | nao altera multiplayer; prepara diagnostico conclusivo do quinto controle |
| pendente | 0.5.6 | mesma capacidade; hook observacional em `0x11CE60` | nao testado | - | registra participante -> controle local antes/depois do builder; nao altera argumentos |
| 2026-08-27 | 0.5.6 | cinco jogadores reais; mesma capacidade | crash identico em servidor e tres clientes | `Reports/Server.zip`; `Reports/Client 1.zip`; `Reports/Client 2.zip`; `Reports/Client 3.zip` | quinto inteiro de controle sobreposto pelos transforms; entrada direta 4 continha outro `UserImpl`; consumer retornou nulo e crashou em `0x6E022` |
| 2026-08-27 | 0.5.7 | mesma capacidade; roteamento de fonte e controle pela ordem pre-sort | crash identico em servidor e tres clientes | `Reports/Server.zip`; `Reports/client 01.zip`; `Reports/client 02.zip`; `Reports/client 03.zip` | todos falharam em `0x6E022` durante P3: o mod remapeou fonte 3 para a entrada final 4; os reports provaram que a ordem pre-sort nao representa os indices finais |
| pendente | 0.5.8 | mesma capacidade; identidade post-sort, consumer/loadout audit e guard de retorno nulo | nao testado | - | preserva P0-P3; reconstroi somente o controle de extras; audita classe/loadout/recurso e tenta fonte nativa segura antes de abortar apenas o player_create nulo |
| 2026-08-27 | 0.5.9 | mesma capacidade; assinatura e rollback seguro dos hooks no startup | abriu pela Steam e permaneceu estavel por 30 segundos | `Reports/crash.zip`; sessao local `pid18340` | corrigido byte `40` ausente na assinatura de `0x6E010`; processo foi encerrado de forma controlada depois da janela de teste, sem WER ou dump novo |
| 2026-08-27 | 0.5.9 | cinco jogadores reais; identidade/controle post-sort | gameplay completo com cinco controles corretos; nicks duplicados e stall em "Conectando" depois da vitoria | `Reports/Server.zip`; `Reports/client 1.zip`; `Reports/client 2.zip`; `Reports/client 3.zip` | P4 tinha classe invalida 4 e reutilizou o UserImpl de P0 nos quatro PCs; luta e vitoria funcionaram; fechamento manual produziu AV separado de teardown no host |
| pendente | 0.6.0 | mesma capacidade; preservacao da identidade extra e auditoria do resultado | nao testado no jogo | - | repara apenas `UserImpl+0xF8`, preserva P4; observa setter/apply e stall de 1/5/15/30 s |
| 2026-08-28 | 0.6.0 | cinco jogadores reais; identidade e resultado | gameplay com cinco controles, mas movimento do host ausente nos clientes, P4 com classe do host e stall/recompensas ausentes | reports de servidor e tres clientes em `Reports` | P4 permaneceu com `UserImpl+0xF8=0`; todos receberam o fluxo P2P do host; todos aplicaram UI 3/1 sem setter nativo |
| pendente | 0.6.1 | indice de loadout temporario/restaurado e recuperacao host-only do setter | substituida antes do teste | - | restaura identidade 4 e prefere fonte nativa de mesma classe; ainda dependia de uma classe duplicada entre P0-P3 |
| pendente | 0.6.2 | bloco nativo temporario sintetizado do PlayerInfo real e mesma recuperacao de resultado | nao testado no jogo | - | classe, seis equipamentos e armadura exatos de P4+; bloco restaurado byte a byte e indice 4+ preservado para nome/replicacao |
| 2026-08-28 | 0.6.23 | cinco jogadores reais; entrada da missao | crash no host e em pelo menos dois clientes em `EDF5.exe+0xB1D60/0xB1D6B` | `Reports/server.zip`; `Reports/client 1.zip`; `Reports/client 2.zip`; `Reports/client 3.zip`; dump local `EDF5.exe.22376.dmp` | pilha do host `0xB1D60 <- 0x9DD90 <- 0x4BBC3C`; `0x4BB5E1` usou `UserImpl+0xF8=4` para acessar a quinta entrada inexistente de uma tabela visual `stride 0x40` |
| 2026-08-28 | 0.6.24 | identidade P4+ preservada; saida visual do resolver usa `indice % 4`; pilha de emergencia ampliada | visual remap executou, mas host e dois clientes deram crash ao montar o texto da classe de P4 | `Reports/Server.zip`; `Reports/Client 1.zip`; `Reports/Client 2.zip`; `Reports/client 3.zip` | resolver leu classe 256/257 do quinto bloco `0x3E90`; AV em `0x5E741C` no host/cliente 3 e `0x4BC33A` no cliente 1; cliente 2 saiu limpo apos perder a sala |
| substituida antes do teste | 0.6.25 | sidecar pre-rollback de classe/loadout e classe final do HUD limitada a `0..3` | nao testado no jogo | - | reverse posterior mostrou que `parser_result=false` ainda entrega contagem valida e que P4/classe 1 tem uma arma sobreposta pela contagem |
| pendente | 0.6.26 | preservacao da contagem independente do retorno booleano e sidecar com mascara por arma | nao testado no jogo | - | valida `0x42FA69`; aceita contagem saneada com out-failure limpo; P4/classe 1 usa mascara `0x2F` e fallback nativo `0x10` |
| pendente | 0.6.27 | Local Mission Harness F3 host+3/host+4/off sobre UserImpl sinteticos distintos | autoteste offline passou; jogo nao aberto | - | baseline nativa e probe P4; Ready/loadout e l1/l2 automaticos; dummies remotos/inertes; Sync_MissionResult concluido apenas em sessao host-only valida |

## Politica para novos candidatos

1. Registrar RVA, bytes originais, funcao aproximada e motivo da classificacao.
2. Nao alterar uma comparacao de capacidade sem o operando que controla a
   reserva/alocacao correspondente.
3. Validar todas as assinaturas antes da primeira escrita e aplicar o lote como
   uma transacao; em falha, manter os bytes originais.
4. Abertura do jogo e uma etapa separada de sala, entrada na missao e partida
   com cinco jogadores reais.
5. Depois de cada teste, atualizar a tabela acima para `MANUAL-PASS` ou
   `MANUAL-FAIL` e anexar o nome exato do report.
