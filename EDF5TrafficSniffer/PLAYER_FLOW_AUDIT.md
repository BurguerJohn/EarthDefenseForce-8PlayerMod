# Auditoria de indice de jogador e P2P

Atualizado em: 2026-08-28

Executavel suportado: `EDF5.exe` SHA-256
`3512D2A2E61D532C5D12DC0C5FD1AC61F6743E13349AE21301BB8449DD4BAE5F`

Esta auditoria procura limites estruturais no caminho sala -> entrada da
missao -> gameplay sem substituir cegamente constantes `4`. O scanner e a
telemetria nunca iniciam o jogo.

## Resultado estatico v1

Comando:

```powershell
_dev\EDF5TrafficSniffer\build\player_flow_scanner.exe EDF5.exe
```

Depois de um teste, os callers P2P observados tambem podem ser fornecidos como
raizes adicionais (um ou mais RVAs):

```powershell
_dev\EDF5TrafficSniffer\build\player_flow_scanner.exe EDF5.exe 0x<caller_rva>
```

O scanner percorreu nove raizes comprovadas de fluxo, 3.552.870 instrucoes e
encontrou:

- 28 callers do getter generico de handles indexados em `0x7e240`;
- tres callers exatos dentro do pipeline da missao;
- quatro comparacoes imediatas com `4` nas nove funcoes-raiz;
- nenhuma mascara `& 3`, `& 0x0f`, bit-test ou shift variavel nessas raizes;
- 74 acessos com indice escalado, dos quais 15 ficam proximos do bound nativo
  no consumer `0x3123a0`.

Resumo esperado:

```text
summary seed_functions=9 indexed_lookup_callers=28 confirmed_mission_lookup_callers=3 compare_four=4 and_mask_3=0 and_mask_f=0 bit_index=0 variable_shift=0 scaled_index=74 indexed_near_four=15 direct_calls=326
```

## Callers de missao classificados

| Call RVA | Contexto | Tabela | Acao |
|---:|---|---|---|
| `0x11CF08` | criacao do jogador | vetor de `net::UserImpl` copiado da sessao | localiza o `UserImpl` esperado pela identidade salva da sessao; caso ele esteja ausente usa `index % 4` como protecao contra crash |
| `0x11DFCE` | transferencia de registros | vetor local com tamanho dependente do fluxo | preservar indice; auditar antes do getter |
| `0x11E057` | anexacao de registros | mesmo vetor local dependente do fluxo | preservar indice; auditar antes do getter |
| `0x126D24` | consumo do vetor temporario de participantes | vetor produzido no proprio fluxo | preservar indice; armazenamento temporario externo comporta oito |

Os tres primeiros callsites possuem assinaturas exatas verificadas antes da
instalacao do hook. Os dois vetores locais nao sao reduzidos modulo quatro sem
evidencia de dump: isso poderia trocar dados reais dos jogadores 5-8 pelos dos
jogadores 1-4.

## Origem da fonte de controle

O reverse estatico da funcao `0x11D5E0` mostrou duas chamadas virtuais no
objeto de sessao: o slot `+0x20` produz a colecao primaria e o slot `+0x28`
produz o subconjunto de controles locais. Ambas sao copiadas por `0x12B200` como
vetores de handles compartilhados de 16 bytes. Objetos reconhecidos usam a
vtable `net::UserImpl` em `0xEC2730`. O baseline 0.5.4 com dois jogadores
mostrou que a primeira colecao possui os dois usuarios e a segunda e um
subconjunto exato de um objeto. O reverse do loop chama o slot virtual `+0x60`
somente para objetos desse subconjunto; `objeto+0x190` vale zero em ambos os
processos. Portanto a 0.5.5 classifica esse campo como indice do controle local,
nao como posicao global do participante.

O builder em `0x11CE60` recebe a colecao primaria e entrega cada objeto ao
consumer `0x3123A0`. O dword `UserImpl+0xF8` lido por esse consumer e o seletor
de classe: o bound `< 4` em `0x312403` corresponde exatamente a Ranger, Wing
Diver, Air Raider e Fencer. Ele nao e um limite de participantes e deve
permanecer em quatro. A fonte `UserImpl`, por outro lado, nao e um ponto de
spawn nem um slot neutro: reciclar o jogador 5 para a entrada 0 pode duplicar
identidade/controle. A 0.5.5 intercepta somente as duas copias comprovadas,
compara as colecoes sem registrar ponteiros e usa uma quinta entrada nativa
automaticamente quando ela chega ao builder. Nao e criada uma entrada
artificial sem evidencia sobre ownership e lifetime.

O mesmo reverse confirmou o contrato de `0x11CE60`: o quarto argumento e o
indice global do participante e o quinto e o indice do controle local produzido
por `0x11D5E0`. Em `0x11D277`, valor negativo segue o caminho remoto; valor
nao-negativo e passado a `0x2DBBC0`, que associa o personagem ao controle local.
Existem somente dois calls diretos, `0x11DC34` e `0x11ECE9`. A 0.5.6 os valida
por assinatura e audita esse limite sem mudar nenhum argumento.

Os quatro reports do teste 0.5.6 com cinco jogadores fecharam a falha imediata.
Servidor e tres clientes sofreram a mesma leitura invalida em `0x6E022`, ainda
dentro do builder do participante 4. A chamada anterior a `0x3123A0` devolveu
um personagem nulo; em seguida o codigo nativo formou `rcx=0x10` e tentou ler
`[rcx+8]`. A entrada final 4 existia, mas o consumer nao conseguiu construir
um personagem a partir dela. A diferenca entre seu ordinal de registro e o
indice do participante ainda nao provava troca de identidade: essa conclusao
dependia de conhecer a ordenacao posterior do produtor.

O reverse de `0x11D5E0` tambem encontrou o motivo de todos os processos
classificarem o participante 4 como local. O caller reserva os inteiros de
controle em `[rbp+0x1D0]`; cinco valores ocupam ate `[rbp+0x1E0]`. Logo depois,
o proprio caller grava 64 bytes de transforms a partir de `[rbp+0x1E0]`,
sobrescrevendo exatamente o quinto inteiro com zero antes do loop de criacao.
Esse zero falso era passado ao binder local em servidor e clientes.

A 0.5.7 tentou corrigir os dois argumentos pela identidade observada nas
copias. O teste seguinte mostrou por que isso estava errado: em servidor e
tres clientes, o mod remapeou o participante 3 da fonte final 3 para a fonte
final 4 e todos falharam novamente em `0x6E022`, antes de chegar ao
participante 4.

O reverse completo de `0x11D5E0` localizou duas chamadas a `0x131F10`
imediatamente depois dos hooks de copia (`0x11D6FE` e `0x11D723`). Essa rotina
ordena os dois vetores. Para cinco entradas ela cai no insertion sort em
`0x132CC0`; o comparator chama o slot virtual `+0x50`, que em `UserImpl` e
`0x452E70` e retorna o qword em `UserImpl+0x184` (SteamID). O movimento em
`0x132DAF` produz ordem decrescente. Somente depois disso `0x11D750` compara a
colecao completa com o subconjunto local, escreve os controles e `0x11D7D3`
entrega a tabela final ao builder. Assim, participante N e entrada N da tabela
final; a ordem das copias pre-sort serve apenas para testes de pertinencia.
Os logs nunca registram o valor da chave/SteamID.

A 0.5.8 preserva integralmente fonte e controle de P0-P3. Para P4-P7, o
controle local e reconstruido usando a entrada N da tabela final e pertinencia
por objeto ao subconjunto local; remoto vira `-1`, e local usa
`UserImpl+0x190`. O segundo caller `0x11ECE9` tambem recebe essa mesma tabela
final produzida por `0x11D5E0`, portanto usa a mesma regra.

O reverse completo de `0x3123A0` mapeou ainda a selecao de recurso. A classe em
`UserImpl+0xF8` escolhe um bloco de `0x3E90` bytes no estado global apontado por
`EDF5.exe+0x125AB30`. O loadout ativo fica em `+0x14B30`; cada registro mede
`0x18` bytes e o seletor de recurso fica a partir de `+0x14B38`. Classe fora de
0..3, recurso negativo ou falha da factory `0x6138E0` levam a retorno nulo.
Para extras, a 0.5.8 prefere uma das quatro fontes nativas utilizaveis da mesma
classe, tenta as demais se o consumer ainda falhar e registra todos os
resultados. Se nenhuma produzir personagem, o hook restrito ao helper
`0x6E010` reconhece somente `source=0x10` durante `mission_player_create`,
devolve um handle vazio e permite ao caminho nativo abortar aquele builder sem
processar a leitura fatal de `0x6E022`.

## Teste de cinco jogadores da 0.5.9

Os quatro reports disponiveis (host, P2, P4 e P3 locais) confirmaram todos os
cinco `mission_player_create_result`, cinco objetos/controls distintos e
exatamente um dono local por computador. Isso encerra a falha de associacao de
controle. Em todos os processos, contudo, P4 tinha `class_selector=4`. Como a
0.5.8 tratava essa classe como fonte invalida, `MissionSourceLookupHook`
devolvia a entrada de P0 inteira. O personagem continuava jogavel, mas a
identidade usada por nome/chat/resultado deixava de ser a de P4.

A 0.6.0 conserva a entrada P4 da tabela final e altera somente
`UserImpl+0xF8` quando ele esta fora de 0..3, copiando uma classe valida da
fonte nativa modulo quatro. O evento `mission_source_identity_repaired`
registra classe anterior/nova e o ordinal da fonte da classe, sem gravar
SteamID ou ponteiro. Se o campo continuar invalido, o fallback integral antigo
permanece como ultima protecao contra crash.

O teste tambem venceu a fase, mas o host ficou indefinidamente em
"Conectando" antes de sair da missao. O fechamento manual ocorreu antes de uma
transicao mission->result observavel e gerou depois um AV de teardown em
`EDF5.exe+0x92C643`; esse AV e consequencia do encerramento forcado, nao o ponto
original do stall. A 0.6.0 instrumenta os dois estagios nativos do resultado:
setter `0x111080` e apply `0x114BB0`. O clear natural chama o setter em
`0x3D8153` com resultado 1. O setter grava `manager+0x34`; o apply leva a UI em
`+0xF8` ao estado 3 e conserva o resultado em `+0xFC`. Checkpoints de
`mission_result_progress` em 1/5/15/30 s mostram qual desses marcos ocorreu e
se a transicao continua pendente.

## Comparacoes com quatro revisadas

### Revisao posterior ao teste 0.6.0

O campo `UserImpl+0xF8` foi reclassificado como indice do bloco nativo de
loadout, nao classe. `0x3123A0` limita o indice a quatro, multiplica por
`0x3E90` e acessa o loadout selecionado em `+0x14B30`. A classe real e
observada ao converter o `UserImpl` em `PlayerInfo` em `0x422F00`, destino
`+0x28`. Portanto P4 deve usar temporariamente um bloco nativo compativel para
construir o personagem e voltar a 4 antes da replicacao normal.

Os reports mais recentes tambem provaram que os clientes recebiam o fluxo P2P
volumoso do host; a perda de movimento ocorria depois do transporte. A colisao
persistente `[0,1,2,3,0]` e a causa concreta que a 0.6.1 remove. Na saida da
fase, o apply 3/1 sem setter veio do retorno `0x114FEF`; a recuperacao e
host-only, exige mais de quatro membros e reutiliza o setter `0x111080` no
thread de `Mission()` apos 250 ms.

### Revisao 0.6.2: conteudo do bloco de loadout

O stride `0x3E90` nao precisa ser apenas reciclado por classe. O parser em
`0x42F7C9..0x42F945` e o consumidor em `0x31240C..0x3124D2` provam o mesmo
layout ativo: seletor de classe no inicio do bloco, registro de seis dwords em
`+8+classe*0x18` e armadura inteira em `+0xF8`. A conversao
`UserImpl -> PlayerInfo` fornece exatamente classe, seis equipamentos e
armadura sem confundir nenhum deles com `UserImpl+0xF8`.

A 0.6.2 faz snapshot/restauracao integral de um bloco nativo durante a criacao
de P4+, injeta nele esses campos do `PlayerInfo` e restaura depois o indice
exclusivo 4+. Isso elimina tanto a classe Air Raider herdada do host quanto a
dependencia provisoria de haver uma fonte 0..3 da mesma classe. Os eventos
`mission_source_loadout_fallback_installed` e
`mission_player_create_result` registram se o bloco foi sintetizado e
restaurado, sem nome, SteamID, payload ou ponteiro.

| RVA | Classificacao | Decisao |
|---:|---|---|
| `0x11DF8F` | construcao/copia da tabela local nativa de quatro registros | manter 4; extras vivem nos sidecars |
| `0x312403` | limite dos quatro blocos nativos selecionados por `UserImpl+0xF8` | manter 4; sintetizar/restaurar temporariamente o conteudo do bloco para P4+ |
| `0x561E75` | indice de uma estrutura de sala com stride `0xDD0` | manter; `indice >= 4` ja seleciona fallback em `objeto+0x3748` |
| `0x561E9E` | segunda leitura da mesma estrutura | manter pelo mesmo fallback seguro |

## Callers genericos adiados

Os 24 callsites abaixo usam o mesmo getter `0x7e240`, mas ainda nao ha
evidencia de que seus indices representem jogadores. Permanecem inalterados:

```text
0x3EE667
0x40C550 0x40CCDC 0x40CCF9 0x40CE00
0x418A7A 0x418FCF 0x4190B6
0x422AEB 0x424F1D
0x42E519 0x42E5B9 0x42E5C9 0x42E5DF 0x42E6BA 0x42EA23 0x42EAB1
0x43843F 0x438526 0x438D06
0x4498B6
0x45293F 0x452A0E
0x5A4384
```

## Telemetria preparada para o proximo teste

- `mission_source_index_audit`: registra uma unica vez cada indice extra por
  contexto, seu indice efetivo, presenca/tipo das entradas solicitada e efetiva,
  ordem no registro de `UserImpl`, classe/loadout/recurso, mascaras de fonte
  utilizavel e controle local, e se a tabela final esta ordenada corretamente
  sem registrar a chave SteamID. O breadcrumb e gravado
  antes do getter, portanto aparece no contexto de crash mesmo se o acesso
  seguinte falhar.
- `mission_source_resolution_audit`: depois do getter, confirma se o objeto
  devolvido e a entrada efetiva, a fonte zero ou outro item registrado, sem
  serializar ponteiros.
- `mission_source_collection_audit`: registra separadamente
  `session_all_users` e `session_local_controls`, incluindo contagem,
  objetos/controls unicos, indices de controle local e o vetor ordinal
  `source_to_registered_order`.
- `mission_source_collection_compare`: mostra o delta, a mascara de entradas
  locais na colecao completa e mapas ordinais por objeto e por control block
  entre as colecoes, sem serializar ponteiros.
- `mission_player_control_assignment`: antes da criacao, registra para cada
  processo e participante os indices de controle original e efetivo, se houve
  correcao por identidade e o indice no subconjunto local; `-1` significa
  remoto e `0+` significa controlado localmente. O breadcrumb precede a funcao
  original.
- `mission_player_create_result`: confirma que o builder retornou e que o
  handle de personagem foi preenchido. A ausencia deste evento depois de uma
  atribuicao localiza um crash dentro de `0x11CE60`.
- `mission_source_consumer_result`: registra resultado direto, mascaras de
  loadout/recurso, fontes nativas tentadas, qual retry construiu o personagem
  e a etapa exata do nulo (`source`, `class`, `loadout`, `resource` ou factory
  `0x6138E0`). A classificação da factory é marcada como inferência estática.
- `mission_null_character_guarded`: prova que todas as fontes falharam e que o
  retorno nulo foi convertido em handle vazio no helper `0x6E010`; inclui o
  participante e a fonte efetiva, nunca ponteiros ou SteamIDs.
- `player_info_class_observed`: associa internamente cada `UserImpl` a classe
  real do `PlayerInfo`; o evento registra apenas ordinal e seletores.
- `mission_source_loadout_fallback_installed`: registra indice original,
  fallback temporario, classe real solicitada/fallback e preservacao do objeto.
- `mission_player_create_result`: alem do handle, confirma que o indice 4+ foi
  restaurado depois da construcao do personagem.
- `mission_result_setter` e `mission_result_apply`: registram resultado,
  caller RVA, estado antes/depois e contagens; o caller de clear natural e
  classificado sem expor enderecos absolutos.
- `mission_result_progress`: aos 1/5/15/30 s resume resultado, estado da UI,
  contagens setter/apply, `Exec_Begin`, sync e recompensas, idade do ultimo
  update e fase diagnostica. O evento
  `mission_result_transition_completed` confirma a saida normal do lobby.
- `mission_result_exec_begin`: observa a entrada RTTI-confirmada
  `net::MissionResult::Exec_Begin(int)` em `0x42FD20` e seu retorno booleano.
- `mission_result_sync_begin`/`mission_result_sync_poll`: classificam somente
  os quatro callers exatos de `Sync_MissionResult` nos helpers compartilhados
  `0x41F820/0x41F920`; registram origem script/network e os dois inteiros de
  estado, sem nome da sync, ponteiro ou payload.
- `mission_reward_resolve`/`mission_reward_apply`: delimitam os wrappers
  `ResolveResult()` e `ApplyResult(bool)`, seu retorno e a contagem 1..2 de
  perfis locais. IDs/conteudo de armas e dados de save nunca sao gravados.
- `chat_name_association`: fixture historica do analisador. A 0.6.48 nao emite
  mais esse evento em runtime, pois o argumento antes tratado como nome e o
  texto da mensagem. `chat_identity_context` o substitui com comparacoes apenas
  booleanas de sala/remetente, sem SteamID, lobby ID, nick ou texto.
- `network_summary/p2p_callsite`: agrega direcao, canal, caller RVA, contagem,
  bytes minimo/maximo e falhas. Nao inclui SteamID, IP, payload ou endereco
  absoluto.
- `network_summary/game_packet_route`: agrega a rotina produtora de envio ou o
  callback consumidor de recepcao, canal, quantidade e tamanhos minimo/maximo.
  O inventario possui 128 slots fixos, nao aloca no caminho de rede e nao
  registra destinatario, SteamID, IP nem payload.
- `network_summary/game_message_route`: agrega mensagens logicas de saida e
  entrada por
  codigo/familia/flags, RVA produtor, presenca do handle de contexto, contagem e
  tamanho. Distingue mismatch inesperado de header de um contêiner multipart
  `0x1100` conhecido. Le somente o header de quatro bytes e nunca guarda
  payload ou identidade de endpoint.
- Os eventos P2P detalhados de perfil `Maximum` tambem recebem `caller_rva`,
  permitindo ligar um formato de pacote a uma rotina exata do `EDF5.exe`.

## Baseline com dois jogadores reais

Os reports de host e cliente com uma fase completa confirmaram o caminho de
transporte normal sem falha:

| RVA observado | Direcao/canal | Classificacao |
|---:|---|---|
| `0x41AC53` | envio / canal 0 | retorno do `SendP2PPacket` normal |
| `0x41AE85` | envio / canal 2 | ticket de autenticacao Steam; nao e gameplay |
| `0x41A460` | recepcao / canais 0-2 | retorno do leitor P2P central |

O produtor logico acima do Steam fica em `0x453890`; seu unico transporte
direto chama `0x41ABE0` em `0x4538EF`. O distribuidor central de recepcao fica
em `0x41A770`, chamado por `0x41A5DB`; ele percorre a lista protegida em
`objeto+0x88` e invoca o segundo metodo de cada callback. A 0.5.3 valida os
prologos, o corpo do loop e os dois alvos de call antes de instalar esses hooks.

O cliente desse teste encerrou com `0xC0000005` em `EDF5.exe+0x991C08` logo
depois de `end_auth_session` e `leave_lobby`, quando as interfaces Steam ja
tinham sido zeradas. Isso aponta para teardown/stale pointer, nao para o caminho
de capacidade da missao, mas ainda e uma inferencia: faltavam registradores e
return address porque o filtro final de crash nao foi chamado. A 0.5.3 grava
`crashes/first-chance-emergency.json` diretamente no VEH para preservar esse
contexto mesmo quando outro componente substitui o filtro top-level.

O reverse do produtor `0x432D20` e de seu unico chamador direto `0x45EAD0`
tambem classificou as familias frequentes `0x3300` e `0x3400`. O codigo e
montado como `((objeto+0x40 << 4) | subtipo) << 8` e depois encapsulado no
header da mensagem; portanto `0x33`/`0x34` sao subtipos dinamicos de uma camada
de replicacao, nao indices dos jogadores 3 e 4. O produtor final continua sendo
observado em `0x432EDA`, sem captura de payload ou identidade de endpoint.

A 0.6.4 fecha a associacao por participante que faltava nesse ponto. O
`SharedProperty` em `0x45EAD0+self+8` fornece o `UserImpl` de origem antes da
serializacao. No caminho de recepcao, `0x4339DC` e o unico call direto de
`0x435670` e passa `UserImpl+0x88`; o parser percorre as mensagens e chama os
handlers sincronicamente. Um escopo thread-local liga por isso o dispatcher
`MissionScript` ao mesmo `UserImpl` sem ler ou registrar o payload. Contadores
das familias `0x3300/0x3400` sao emitidos por P0-P7, e qualquer contexto que
nao estiver no mapa final da missao cai explicitamente no bucket nao resolvido.

A revisao offline posterior da 0.6.10 percorreu os tres trechos completos:
produtor `0x45EAD0`, serializador `0x432D20` e parser remoto `0x435670`. Nao ha
comparacao, mascara ou array de quatro participantes nesses caminhos. O
imediato `4` em `0x432DC9` e o tamanho do header da mensagem; os `& 0xF` em
`0x45EB5B/0x45EB77` combinam o subtipo no codigo `0x33xx/0x34xx`. Portanto nao
foi aplicado nenhum patch especulativo de capacidade na rede.

O analisador agora oferece `--require-replication-matrix`. Em cada capture ele
exige saida `0x3300/0x3400` associada ao participante controlado localmente e
entrada associada a cada participante remoto. Assim um cliente que recebe P2,
P3 e P4, mas nao recebe o host P0, deixa de passar apenas porque havia "algum"
trafego de entrada. A fixture negativa reproduz exatamente esse caso e precisa
ser rejeitada.

O primeiro teste com cinco jogadores reais chegou ao gameplay sem crash, mas
teve lag/desincronizacao severos e personagens que nao se moviam ou pareciam
compartilhar controle. Nos quatro reports disponiveis, o jogador de indice 4
foi reciclado para `source_index=0`. Isso motivou a auditoria das duas colecoes
e das mensagens na 0.5.4. No proximo teste, os novos eventos devem dizer se o
quinto `UserImpl` se perde na colecao completa, na resolucao do getter ou na
associacao local de controle, e se o fluxo de mensagens diverge entre PCs.

O teste 0.5.4 posterior com dois jogadores completou a fase nos dois lados e
confirmou `session_all_users=2`, `session_local_controls=1`, dois objetos
distintos e transporte P2P sem falhas. A 0.5.5 acrescenta a permutacao ordinal
e a resolucao final necessarias para decidir se cada PC associa o quinto
participante ao mesmo `UserImpl`; o fato de o teste anterior com cinco pessoas
ter criado cinco personagens concentra a investigacao em identidade/controle e
sincronizacao depois do spawn.

## Resultado, sync e recompensa na 0.6.5

Os reports de host e tres clientes do teste com cinco pessoas foram gerados
pela 0.6.0. Eles confirmam cinco personagens e ownership local distinto para
P0/P2/P3/P4, mas mostram o fallback temporario permanente `P4: 4->0` usando
P0. Isso explica a classe Air Raider e a repeticao de nick observadas. A 0.6.4
ja substitui esse caminho por um bloco nativo temporario que recebe classe,
seis equipamentos e armadura do `PlayerInfo` de P4, e restaura tanto o bloco
quanto o indice exclusivo 4 antes de retornar ao jogo.

Na vitoria, todos os quatro reports registraram UI 3/resultado 1 via apply,
mas nenhum setter nativo. O host so registrou setter de resultado 2 cerca de
210 segundos depois, no abort manual. A recuperacao host-only da 0.6.4 chama o
setter de clear uma vez depois de 250 ms quando esse padrao exato ocorre.

O reverse adicional mapeou a continuacao do fluxo: RTTI/vtable identifica
`0x42FD20` como `net::MissionResult::Exec_Begin`; os xrefs da string
`Sync_MissionResult` chegam a dois pares de calls em `0x3E2DD8/0x3E2DE4` e
`0x42C134/0x42C13B`; os wrappers registrados de script ficam em `0x3E3150`
(`ResolveResult`) e `0x3E3160` (`ApplyResult`). O bloco `0x42C0D6` nao e alvo de
hook: ele compartilha frame/epilogo com uma funcao maior e nao possui entrada
segura. Os hooks usam somente prologos reais e assinaturas exatas.

`ApplyResult` le a contagem em estado global `+0x2459C`, inicia perfis locais
em `+0x6D4C` e avanca `0x3E60` bytes. O unico setter (`0x55830`) aceita apenas
1 ou 2; logo esse limite pertence aos saves locais, nao ao roster online, e
nao deve ser convertido em 5/8/`MaxPlayers`.

Os utilitarios `tools/disassemble_rva.py` e `tools/inspect_vtable.py` permitem
repetir a analise por RVA e RTTI/vtable sem iniciar o jogo.

## Chat, parser de replicacao e despacho do resultado na 0.6.6

As vtables de `net::Chat_Room` levaram ao publicador `0x3F0B70`. Seus tres
callers diretos (`0x3F1635`, `0x3F1863`, `0x3F1F81`) convergem duas identidades,
texto e estado da mensagem nessa unica entrada. A interpretacao da 0.6.6 de
que o texto era o nome exibido foi invalidada por `Reports\msg_bug.zip`; por
isso a 0.6.48 nao usa esse argumento para associar nick a participante.

O unico caller do parser de gameplay `0x435670` esta em `0x4339DC` e passa
`UserImpl+0x88`. O parser itera vetores cujo begin/end sao lidos em runtime e
chama os handlers no mesmo thread. Nao foi encontrada comparacao, mascara ou
array de quatro participantes nesse consumer. Isso reforca que uma futura
divergencia deve ser procurada na associacao `UserImpl -> personagem`, nao em
um novo patch indiscriminado de capacidade nesse parser.

O setter de resultado `0x111080` chama a aplicacao de UI e depois constroi um
evento local de tipo 1/payload 2. Os dois caminhos internos chamam `0x61E950`,
um fanout sincrono sobre listas dinamicas de listeners. A recuperacao host-only
nao e cosmetica porque reproduz o setter original completo; contudo, o reverse
da 0.6.8 prova que esse evento fecha um objeto local de UI e nao inicia por si
so a etapa de sync/recompensa. As duas cadeias sao auditadas separadamente.

## Restauracao pre-map e evento de resultado na 0.6.7

O consumer de personagem `0x3123A0` precisa de um indice nativo 0..3 somente
durante a construcao. A continuacao de `MissionPlayerCreate`, contudo, volta a
ler `UserImpl+0xF8` em `0x11D0EC` e `0x11E061`; a segunda leitura alimenta uma
arvore/mapa de runtime. Deixar P4 com o fallback `0` ate o retorno da funcao
inteira cria uma colisao concreta com P0. A restauracao agora acontece no
retorno imediato do consumer e registra fase, indice observado antes/depois e
se ocorreu antes dos consumers do mapa. O validador rejeita a fixture que
restaura apenas em `player_create_return_fallback`.

O publicador tipado `0x61E950` foi instrumentado com escopo thread-local apenas
durante `MissionResultSetterHook`. Assim, o report distingue: UI de vitoria,
setter, publicacao esperada `tipo=1/payload=2`, `Exec_Begin`, sync, resolve e
apply. Fora do setter, o hook e um pass-through sem telemetria por evento. O
argumento de `Exec_Begin` foi renomeado para valor opaco; os dois callers
comprovados passam respectivamente `-20000` e um parametro recebido, portanto
ele nao representa diretamente o resultado clear `1`.

## Alvo UI do evento e separacao da sync na 0.6.8

O global usado pelo setter aponta para a interface secundaria de
`xgs::ui::System`; subtrair `0x88` recupera o barramento dono das listas em
`+0x18` e `+0x28`. O fanout `0x61E950` chama o callback virtual `+0x18` de cada
listener. O callback generico de `xgs::ui::Object` fica em `0x4A1B70`: evento
tipo `1` compara o payload com `Object+0x78`, e o match `2 == 2` marca o bit 0
em `Object+0x18` antes de invocar a transicao virtual de fechamento.

Esse callback nao chama `0x42FD20`, `0x41F820` nem `0x41F920`. Portanto o
report agora registra `mission_result_ui_close_dispatch` separadamente de
`mission_result_exec_begin`, `mission_result_sync_begin/poll` e rewards. O
evento contem apenas inteiros/booleans: ID do listener, match do alvo, flag de
fechamento antes/depois e retorno; nenhum endereco absoluto ou payload e
persistido. Uma fixture positiva exige o fechamento do objeto 2 e uma negativa
com listener 5 prova que o analisador detecta o alvo ausente.

## Filtro de participantes do MissionSync_Res na 0.6.9

A vtable RTTI de `MissionSync_Res` aponta a entrada principal `0x42D8A0`. Ela
percorre a colecao viva de `UserImpl`, valida `+0xC1/+0xC0` e, em `0x42DB3E`,
le o indice exclusivo `UserImpl+0xF8`. O teste `cmp eax,4` em `0x42DB4C`
eliminava P4-P7 antes de anexar seu shared handle. Isso e um limite de
participantes online, nao de classes.

O destino comecava com `reserve(4)`, mas o caminho `0x42DBDC` dobra a
capacidade e cada handle ocupa 16 bytes. O consumer de `0x42DE34` itera pela
quantidade dinamica e grava o agregado em `state+0x245A0`; ele nao usa o indice
do jogador para enderecar uma tabela de quatro posicoes. Por isso a 0.6.9 liga
somente o operando de `0x42DB4C` a `MaxPlayers` e mantem todos os loops de
quatro classes e o count 1..2 de perfis locais de `ApplyResult` inalterados.

Assinaturas exatas cobrem o filtro, o grow dinamico, o loop por size e o commit.
O patch integra a mesma transacao de protecao, escrita e verificacao do roster;
qualquer divergencia de bytes deixa o plugin em quarentena antes dos hooks.

## Rollback do parser de loadout e retorno efetivo na 0.6.10

O reverse do parser completo em `0x42F480` revelou uma sobreposicao que nao
aparece no consumer isolado de criacao. O parser conserva o indice logico real
do participante e calcula `state+0x14B30+indice*0x3E90`. Portanto o bloco de P4
comeca em `state+0x24570`; dentro desse mesmo quinto bloco ficam o contador de
perfis locais de recompensa em `+0x2459C` e o agregado de participantes do
resultado em `+0x245A0`. O parser escreve seletor, equipamentos, armadura e
outras regioes do bloco, de modo que apenas corrigir a classe nao impediria a
corrupcao do fechamento da fase.

A 0.6.10 envolve o parser inteiro: faz snapshot dos quatro blocos extras
P4-P7 (`4 * 0x3E90`), chama o original com os registros e indices verdadeiros,
restaura byte a byte a regiao fora dos quatro blocos nativos e, somente quando
o parse termina com sucesso, preserva o contador final legitimo em
`+0x245A0`. O contador local em `+0x2459C` e todo o restante voltam aos valores
anteriores. Nenhum indice sintetico e serializado, portanto nome, chat,
replicacao e ownership continuam associados ao `UserImpl` real.

Outro consumer em `0x4B6710` tambem multiplicava `UserImpl+0xF8` por `0x3E90`
sem limite. O hook sidecar da 0.6.10 deixa o indice logico 4+ intacto, mas
substitui a classe de saida pela classe observada no `PlayerInfo` daquele mesmo
participante. Isso cobre os callers de criacao que nao passam por `0x3123A0`.

Por fim, `MissionUpdateHook` agora devolve `clear=1` quando a recuperacao
host-only do setter ocorreu no mesmo tick e o retorno nativo capturado antes
dela ainda era zero. Antes, o setter podia publicar o resultado, mas o script
recebia o zero obsoleto e deixava de iniciar sync/recompensa. As assinaturas do
prologo do parser, do resolver de classe e os offsets sobrepostos fazem parte
do fail-closed; o self-test sobrescreve toda a faixa extra e prova a restauracao
exata, com excecao intencional do contador de participantes.

## Callback e vetor dinamico de recepcao na 0.6.12

O unico caller direto de `0x435670` continua em `0x4339DC`, mas agora o nivel
anterior tambem foi revertido. A entrada `0x4336F0` e alcancada por um callback
virtual cujo thunk em `0x451B90` recupera o owner em `callback+0x18`. O pump
le a quantidade qword em `owner+0xE0`, a base em `owner+0xD0` e calcula cada
shared handle com `indice << 4`. O backedge `0x433B6C` compara o indice com a
quantidade lida em runtime; nao ha `cmp 4`, mascara de dois bits ou tabela
local de quatro entradas nesse caminho.

Cada shared handle contem um `UserImpl`, e o pump passa `UserImpl+0x88` ao
parser. O hook observacional da 0.6.12 usa a mesma trava em `owner+0x80`, sem
esperar caso esteja ocupada, e compara a tabela com o mapa privado de
participantes. O evento resultante informa somente contagem, mascaras P0-P7,
legibilidade e completude. Fixtures isoladas provam tres casos: cinco rotas
unicas completas, P0 ausente e P0/P4 duplicado.

## NetGameStatus e acumuladores do resultado na 0.6.13

O decoder compartilhado `0x430C20..0x4312FE` recebe uma funcao com assinatura
`void(int, NetGameStatus::Item const&)`. A quantidade de Items vem de um inteiro
de tamanho variavel e o loop de parse percorre todos os registros recebidos.
Entretanto, `0x430F23` comparava o indice logico com quatro e pulava o callback
para P4-P7. Isso deixou `MissionSync_Res` com cinco handles desde a 0.6.9, mas
o estado de resultado ainda com dados de apenas quatro participantes.

O thunk exato da funcao fica em `0x132BB0`: ele carrega o indice e grava o qword
em `state+0x2457C+indice*8`. A inicializacao em `0x430EF6` limpa quatro qwords e
deve permanecer assim, pois o quarto termina exatamente antes do contador de
perfis locais em `+0x2459C`. Nao existe espaco contiguo para transformar essa
tabela em oito entradas.

A 0.6.13 liga apenas o filtro de aplicacao `0x430F23` a `MaxPlayers` e intercepta
o thunk. Indices 0..3 seguem inalterados; cada Item extra e somado nos dois
dwords do slot `indice % 4`. Os consumers nativos `0x12AA30`, `0x60E80`,
`0x60F40` e `0x1991D0` reduzem os quatro slots, portanto preservam o total de
cinco a oito participantes sem indexacao fora do bloco. Assinaturas exatas,
self-test isolado e fixture do analisador cobrem o filtro, o thunk, a soma P4 e
a ausencia intencional de conteudo de reward/payload nos logs.

## Origem do nickname e consumers de reward na 0.6.14

O construtor exato `PlayerInfoFromUser` em `0x422F00` recebe o destino em RCX e
o `SharedProperty` fonte em RDX. Depois de conservar o `UserImpl` fonte, ele
chama o getter virtual `+0x10` ou `+0x08` do mesmo objeto e copia a string
resultante para `PlayerInfo+0x08`. Nao existe uma tabela paralela de quatro
nomes nesse trecho. Portanto uma troca P0/P4 nasce antes, pela colisao do
`UserImpl`/indice, ou depois, quando o chat associa remetente e nome; ela nao
deve ser corrigida substituindo texto cegamente.

A 0.6.14 registra, sem texto ou identidade externa, o indice logico do
`UserImpl` que originou cada `PlayerInfo`, quantos objetos compartilham o token
privado do nome e se o indice ainda coincide com o participante durante a
criacao do personagem. A associacao adicional pelo publicador comum do chat
foi tentada nessa versao, mas desativada na 0.6.48 depois que o quarto argumento
foi reclassificado como mensagem. A origem dos nomes continua auditada no
proprio caminho `PlayerInfo`, sem persistir nickname, SteamID, ponteiro,
mensagem ou endpoint.

O reverse tambem percorreu os consumers finais. `0x12AABE..0x12AAFB` e
`ResolveResult 0x199275..0x1992A9` reduzem exatamente os quatro Items contiguos
em `+0x2457C`; eles produzem totais e nao indexam jogadores. Em seguida,
`0x199492` distribui esses totais pela contagem dinamica de perfis locais em
`+0x2459C`, com stride `0x3E60`. O `ApplyResult` real em
`0x199D50..0x199EC7` percorre um vetor dinamico de registros de 20 bytes e
itera separadamente os perfis locais. Nao existe outro limite online de quatro
nessas funcoes.

Esses corpos agora possuem assinaturas exatas no validador. Antes de
`ResolveResult` e depois de `ApplyResult`, a telemetria compara a contagem de
participantes com a mascara de Items extras ja agregados. Ela informa apenas
contagem, mascara e completude; nenhum valor de arma/recompensa ou payload e
gravado. A 0.6.14 nao inventa rewards nem altera o algoritmo nativo: ela torna
conclusivo se P4-P7 chegaram ao ponto em que os rewards sao resolvidos.

## Rota de transporte independente na 0.6.15

O indice de participante/loadout em `UserImpl+0xF8` nao seleciona sozinho a
rota que recebe mensagens. O alocador dinamico em `0x45C8E3` encontra um slot
no vetor `manager+0xD0`, cuja contagem e lida de `manager+0xE0`. O indice segue
para o construtor em `0x45C948` e e persistido em `UserImpl+0xC8` por
`0x4525FB`. O registrador `0x433BD0` le `+0xC8` em `0x433C78`; o destrutor usa
o mesmo campo em `0x433E3C` para remover a rota.

Esses loops e vetores sao dinamicos, portanto nao justificam um patch de
capacidade. O risco relevante e uma colisao ou um indice fora de posicao: por
exemplo, P0 e P4 com `+0xC8=0` deixam a rota do host ausente ou substituida em
um cliente. A telemetria agora fornece arrays ordinais de rota, participante e
indice armazenado, alem de mascaras de ausentes, duplicados e divergencias. O
analisador cruza esses valores com a criacao de personagem e com as familias
de replicacao `0x3300/0x3400`. Todos os dados continuam privados e
sanitizados; nao ha IDs, nomes, endpoints nem payloads.

## Fan-out por descritor de rota na 0.6.17

O produtor `0x45EAD0` chama `0x432D20` em `0x45EB9B` passando um vetor dinamico
de descritores de rota. O builder `0x45ED80` percorre uma colecao viva de
usuarios, copia o qword `UserImpl+0xC4` e o anexa com stride 8. O segundo dword,
em `descritor+4`, e lido por `0x433F40` e usado como indice da tabela dinamica
`manager+0xD0`. Isso prova que o elemento nao e um `SharedProperty` de 16 bytes;
a instrumentacao 0.6.16 com essa hipotese foi substituida antes do teste.

A auditoria 0.6.17 conserva em TLS apenas o `UserImpl` local durante a chamada
e mede o vetor imediatamente antes de devolve-lo ao jogo. Para cada familia
`0x3300/0x3400` e participante local, o primeiro evento informa quantidade de
rotas validas/unicas, mascara P0-P7 observada, remotos ausentes/inesperados,
duplicados, nao resolvidos e resultado do serializador.

Isso permite distinguir um produtor local saudavel com quatro destinos de uma
falha de publicacao anterior ao P2P. O evento nao serializa os descritores,
indices/chaves de rota, ponteiros, IDs, nomes, endpoints nem conteudo das
mensagens. A fixture positiva
exige um destino remoto unico em uma sessao de dois jogadores; a negativa
simula zero destinos e deve falhar com `--require-replication-send-fanout`.

## Matriz completa dos Items de resultado na 0.6.18

O sink `0x132BB0` recebe todos os indices que passaram pelo decoder
`NetGameStatus`, mas a 0.6.17 registrava apenas os indices extras que exigem
fold. A 0.6.18 marca a presenca legivel de P0-P7 em uma mascara independente
dos valores e conserva a mascara extra separada para provar a agregacao.

Os checkpoints temporais e os hooks de `ResolveResult`/`ApplyResult` publicam
contagem de participantes, mascara esperada, mascara observada e completude.
Isso localiza a espera em um unico report mesmo se rewards nunca forem
chamados. Nenhum conteudo de Item, arma, reward ou payload e registrado. A
auditoria completa de `0x45EAD0/0x432D20/0x4336F0/0x435670`,
`0x42FD20`, `0x41F820/0x41F920`, `0x1991D0` e `0x199D50` nao encontrou outro
limite online de quatro; os filtros comprovados continuam sendo
`MissionSync_Res 0x42DB4C` e `NetGameStatus 0x430F23`, ambos ja corrigidos.

## Recuperacao do contador local de rewards na 0.6.19

O wrapper `ApplyResult` em `0x3E3160` le o dword de perfis locais em
`state+0x2459C`; zero salta diretamente todo o laco que aplica armas aos saves.
Esse campo esta dentro da faixa que o quinto bloco de `0x3E90` sobrescrevia.
O rollback do parser continua sendo a correcao primaria.

Como defesa final, a colecao `session_local_controls`, copiada antes da criacao
dos personagens, fornece uma contagem independente e validada de 1..2 perfis.
Em vitoria com P4+, `MissionRewardApplyHook` troca um contador nativo invalido
por essa contagem imediatamente antes do wrapper original. Nenhum valor de
arma, reward, nome, ID, ponteiro ou payload e lido pelo diagnostico. O
analisador mostra `profiles=antes->efetivo->depois`, o valor esperado e se a
restauracao ocorreu.

## Contrato de retorno de PlayerInfo na 0.6.20

`Reports\Crash.zip` registrou `c0000005` de escrita em `0x55D64D`, com retorno
para `0x560537`, durante a primeira atualizacao da sala e sem fillers. O valor
fonte preservado em R9 era `UserImpl vtable 0xEC2730`; ao copiar o suposto
objeto, o jogo carregou dessa tabela `0x452F70`, a destrutora de `UserImpl`, e
tentou incrementar `+4` como se fosse um contador de referencias. Isso prova
que o vetor recebeu a vtable como ponteiro de `PlayerInfo`, nao que a reserva
de oito slots tenha falhado.

Os callers `0x422087` e `0x422277` chamam `PlayerInfoFromUser 0x422F00` e passam
RAX diretamente ao construtor de handle em `0x425760`. O epilogo do conversor
executa `mov rax,r14` em `0x423962`, onde R14 conserva o destino. O hook de
auditoria introduzido para nomes/classes tinha retorno `void`, portanto a
rotina de observacao sobrescrevia esse registrador depois de o original
retornar. A assinatura agora e `uint8_t*`, o valor original e conservado ate o
retorno do hook, e `0x42395A..0x423964` faz parte da validacao offline. O evento
sanitizado `player_info_return_contract` registra apenas match e contagem de
divergencias; enderecos de destino/retorno nao sao persistidos.

Quando existirem novos reports, a atribuicao de controle pode ser comparada
diretamente entre ZIPs sanitizados, sem extrai-los:

```powershell
python tools/analyze_player_controls.py Reports\*.zip --expected-players 5 --require-exact-loadout --require-pre-map-loadout-restore --require-loadout-parser-rollback --require-class-sidecar --require-name-identity --require-chat-name-association --require-replication-association --require-replication-matrix --require-replication-send-fanout --require-receive-route-matrix --require-transport-route-identity --require-extra-result-items --require-result-item-matrix --require-result-event-publish --require-effective-result-recovery --require-result-ui-close-dispatch --require-result-reward-chain --require-result-room-return --strict
```

Cada processo deve listar todos os participantes, normalmente marcar apenas um
como local e completar `mission_player_create_result` para todos. Donos locais
duplicados entre computadores, consumer nulo ou fallback de fonte extra sao
destacados.

## Identificacao local no chat da sala na 0.6.21

`net::Chat_Room` usa a vtable `0xEBEDA8` e publica as linhas visuais pela rotina
comum em `0x3F0B70`. O caminho nativo de mensagem local inicializa um estado
neutro de `0x50` bytes em `0x3F17F7`, grava `-1` no dword `+0x08` e chama esse
publicador em `0x3F1863` com tipo 2 e subtipo 0. O envio para a Steam ocorre em
outro trecho da rotina nativa, portanto nao e necessario nem desejavel usa-lo
para identificar o mod.

A 0.6.21 agenda `EDF5_MultiSlotMod v0.6.21` quando uma sala criada localmente e
confirmada ou quando a contagem positiva confirma a entrada no lobby solicitado.
O primeiro evento visual valido de `Chat_Room` consome a pendencia e chama
diretamente o trampoline do publicador comum. Isso evita recursao no hook e nao
executa `SendLobbyChatMsg`; a linha existe somente na interface local e nao pode
ser atribuida a outro participante.

Ao sair da sala, tanto o alvo de join quanto a pendencia e a identidade do lobby
sao limpos. O autoteste cobre join assincrono, criacao, estado neutro exato,
texto/versao exatos, sucesso unico, ausencia de duplicacao e limpeza na saida.
Os logs guardam apenas nome, versao, caminho de entrada e resultado da tentativa;
nenhuma mensagem de usuario, nickname, SteamID, endpoint ou payload e persistido.

## Instancia direta de Chat_Room na 0.6.22

`Reports\no_name.zip`, gerado pela 0.6.21, terminou limpo e sem qualquer crash.
Ele registrou `chat_mod_banner_armed` para a sala criada, mas nao registrou
`chat_mod_banner_publish` nem uma unica passagem pelo hook do publicador. Isso
prova que esperar uma entrada visual posterior nao e um gatilho valido.

O unico caller direto do construtor `Chat_Room 0x3F0680` esta em `0x412AFA`.
Ele aloca `0xC0` bytes, constroi o objeto e o guarda no shared handle de sala.
A atribuicao da vtable ocorre em `0x3F06B8` e aponta para `0xEBEDA8`. A 0.6.22
hooka apenas o construtor, valida essas duas assinaturas e conserva a instancia
em um atomico sem registrar seu endereco.

Durante `HUiRoom::Update`, a publicacao so e tentada quando:

1. existe banner pendente;
2. a instancia ainda possui a vtable exata de `Chat_Room`;
3. `ISteamUser019::GetSteamID` devolve uma identidade local valida;
4. essa identidade corresponde a um `UserImpl` registrado.

O retorno `CSteamID` de `GetSteamID` usa o buffer oculto do ABI MSVC, modelado
explicitamente como nos getters de lobby. Um qword zero e passado como
destinatario para escolher a linha publica, enquanto remetente e sempre o
usuario local. A chamada vai direto ao trampoline de `0x3F0B70`, portanto nao
entra no metodo `0x3F16C0` nem em seu envio Steam `0x44D940`.

O autoteste nao fabrica uma mensagem nativa: ele confirma a espera antes do
registro local, a publicacao direta unica ao criar e entrar, o estado neutro de
`0x50` bytes e a ausencia de duplicacao. Se algum pre-requisito faltar em
runtime, `chat_mod_banner_waiting` registra uma vez apenas o motivo sanitizado.

## Estado de texto do Chat_Room na 0.6.23

`Reports\no name v2.zip`, produzido pela 0.6.22, registrou a captura valida do
`Chat_Room` e 755 retornos falsos consecutivos do publicador. Quando o usuario
enviou sua primeira mensagem, o evento nativo ocorreu e a tentativa 756 foi
aceita. Nao houve crash, perda de eventos ou erro de escrita.

O guard de `0x3F0B70` em `0x3F0C04` rejeita uma mensagem fora do editor ativo
quando `state+0x20 == 0`, `state+0x00 == 0` e o ponteiro em `state+0x10` tambem
e nulo. A mensagem local montada em `0x3F17F7` realmente deixa `+0x10` zerado,
pois seu caller esta no contexto do editor. Ja o decoder remoto copia o ponteiro
do texto para esse campo em `0x3F1E72` antes da publicacao em `0x3F1F81`.

A 0.6.23 conserva o estado de `0x50` bytes, a selecao `-1`, tipo 2 e subtipo 0,
mas grava o endereco estatico de `EDF5_MultiSlotMod v0.6.23` em `+0x10`. O
publicador continua sendo chamado diretamente: nao ha passagem pelo metodo de
envio `0x3F16C0`, pelo transporte `0x44D940` nem pela Steam. O falso publicador
do autoteste agora exige essa associacao entre o campo `+0x10` e o argumento de
texto. Rejeicoes reais sao tentadas no maximo a cada 250 ms; somente a primeira
falha sanitizada e o eventual sucesso sao gravados.

## Tabela visual nativa de quatro jogadores na 0.6.24

Os reports `server.zip`, `client 2.zip` e `client 3.zip` registraram a mesma
violacao de acesso durante a abertura da missao: `EDF5.exe+0xB1D60` no host e
cliente 3, e `EDF5.exe+0xB1D6B` no cliente 2. O dump bruto do host preservado
pelo Windows mostrou a pilha `0xB1D60 <- 0x9DD90 <- 0x4BBC3C`. A rotina
`0xB1CF0` copia um descritor grafico de `0x30` bytes e tentou incrementar uma
referencia cujo controle invalido era `0x200000000`.

O chamador `0x4BB010` resolve o `UserImpl`, recebe em sua primeira saida o
indice logico de `UserImpl+0xF8` e, em `0x4BB5E1`, calcula
`render_base + indice * 0x40`. A tabela visual possui somente quatro entradas.
P4 selecionava a quinta entrada nao construida; o crash ocorria depois, ao
submeter esse descritor em `0x4BBC37`. Isso e um limite de recurso visual, nao
de identidade, controle, loadout ou transporte.

A 0.6.24 mantem `UserImpl+0xF8=4..7` e altera somente a saida temporaria do
resolver `0x4B6710` para `indice % 4`. Assim P4-P7 reutilizam os recursos
visuais 0-3 sem colidir no mapa logico. O evento sanitizado
`mission_participant_visual_slot_remapped` registra indice logico, slot visual,
RVA do caller e booleans de preservacao, sem nomes, IDs, ponteiros ou payloads.
Assinaturas exatas cobrem o calculo `*0x40` e a instrucao de crash.

O emergency logger tambem passou a varrer `0x800` bytes da pilha da thread e
guardar ate oito candidatos executaveis como pares `stack_offset/module_rva`.
Esses RVAs continuam no ZIP sanitizado, enquanto enderecos absolutos e dumps
permanecem removidos. O analisador aceita `--stack-hex` para inspecao local do
dump e `--require-visual-slot-remap` para o proximo teste coordenado.

## Classe nativa e tabela de texto fixa na 0.6.25

Os reports `Reports\Server.zip`, `Reports\Client 1.zip`,
`Reports\Client 2.zip` e `Reports\client 3.zip`, todos da 0.6.24, comprovam que
`mission_participant_visual_slot_remapped` executou para P4 antes da nova
falha. Host e cliente 3 terminaram com AV de leitura em `0x5E741C`; cliente 1
em `0x4BC33A`. O cliente 2 registrou saida limpa depois de perder a sala e ficar
no loading, coerente com a queda do host.

O dump local do host (`pid 21544`, mantido apenas localmente) fixa a pilha
`0x5E741C <- 0x4BC2CF`. Em `0x5E741C`, `cmp bx,[r8]` recebeu `r8=1`. O caller
escolhe em `0x4BC266` uma string nativa e a obtem de um registro calculado em
`0x4BB5CE` como `class * 0x30 + [rdi+0xB8]`. Os eventos anteriores ao crash
registraram classe nativa 257 no host e 256 no cliente 3.

A origem e `0x4B6886..0x4B689A`: o resolver multiplica o indice logico por
`0x3E90` e le a classe em `state+0x14B30`. P4 portanto consulta o quinto bloco,
que nao existe e sobrepoe o estado do resultado. O rollback do parser estava
correto, mas apagava junto os dados uteis que o parser havia acabado de produzir.

A 0.6.25 conserva antes do rollback somente os campos comprovados do bloco
extra: seletor de classe, registro ativo de seis dwords e armadura. O sidecar e
indexado por P4-P7, protegido por lock e limpo ao criar/entrar/sair da sessao.
Ele serve tanto para sintetizar o bloco temporario durante a fabrica do
personagem quanto para corrigir a classe do HUD quando `PlayerInfo` nao foi
observado. Como ultima barreira, qualquer classe nativa fora de `0..3` e
substituida pelo slot visual modulo quatro.

O autoteste cobre os dois valores dos reports: classe nativa 257 e ausencia de
`PlayerInfo`, primeiro com sidecar valido e depois sem sidecar, garantindo saida
0 em ambos. A validacao offline cobre exatamente `0x4B6886`, `0x4BB5CE`,
`0x4BC266` e `0x5E741C`. Nenhum jogo foi iniciado durante a implementacao.

## Contrato final do parser e sidecar parcial na 0.6.26

O fluxo completo de `0x42F480` fixa a ordem das escritas. Para P4+, o parser
nao executa a copia grande reservada aos indices 0..3, mas ainda grava seletor,
seis armas, armadura e o final de 0x30 bytes. Depois do loop, `0x42FA69` executa
`mov [state+0x245A0],r12d` sem consultar o valor booleano de retorno. Isso
explica a telemetria real `after_parser=5`, `parser_result=false`: era uma
leitura valida, nao uma falha.

Ha somente um `call` direto para o parser, em `0x42ABDE`. O chamador prepara um
byte de erro em `[rsp+0x38]`, passa seu endereco e o testa em `0x42AC05` para
decidir se devolve `-1`. `0x42F4D2` apenas zera esse byte e nenhum caminho o
torna verdadeiro. Separadamente, o retorno em `AL` apenas marca um estado do
objeto; no caminho de decodificacao, `0x42F73D` zera `r13b` antes das escritas.
Assim, preservar a contagem apenas quando `AL=true` invertia o contrato real.

P4 com classe 1 possui registro ativo em `0x24590..0x245A7`. A arma 3 sobrepoe
o contador local em `0x2459C`, mas ainda contem a arma real no instante da
captura; a arma 4 em `0x245A0` ja foi substituida pela contagem final. A mascara
de validade resultante e `0x2F`, com fallback nativo somente em `0x10`. Para
PlayerInfo a mascara permanece `0x3F`. O autoteste reproduz retorno `false`,
contagem 5, classe 1 e a sobreposicao, exige a preservacao de 5 e verifica que
o scratch recebe `{1040,1041,1042,1043,nativo,1045}` antes de ser restaurado.

Os eventos passam a expor apenas mascaras e estado: `complete_sidecar_weapon_mask`,
`partial_sidecar_weapon_mask`, `participant_count_output_valid`,
`participant_count_source`, `weapon_valid_mask` e `fallback_weapon_mask`.
As mascaras nao adicionam conteudo de equipamento ao report; permanece apenas
o primeiro ID numerico que a telemetria de loadout ja registrava.

## Censo completo dos consumidores de classe/indice visual

O reverse offline encontrou exatamente tres chamadas diretas ao resolvedor
`0x4B6710`: `0x4B8039`, `0x4BB1FB` e `0x4CEEFC`. Nenhuma delas usa a primeira
saida como identidade persistente. Ela alimenta somente indices visuais
transitorios:

- `0x4B855E` calcula `indice*0x30` para uma tabela de descritores de UI;
- `0x4BB5E1` calcula `indice*0x40` para os quatro descritores do status/HUD,
  enquanto `0x4BB5CE` calcula `classe*0x30` para os textos das quatro classes;
- `0x4CF21F` calcula `indice*0x10` sobre um array local que `0x4CEDE5` inicializa
  com exatamente quatro entradas consecutivas. O mesmo caller seleciona apenas
  as classes 0..3 em `0x4CEF24`.

Portanto, dobrar apenas as duas saidas transitorias para 0..3 protege todos os
consumidores conhecidos sem alterar `UserImpl+0xF8`, que continua unico para
controle, nomes e replicacao. O validador agora enumera todas as instrucoes
`E8 rel32` da secao `.text`, exige exatamente esses tres callers e confere os
tres layouts de consumo. Um caller novo ou uma mudanca de layout faz o build
falhar em vez de deixar um caminho visual sem auditoria.

## Concorrencia e ciclo de vida do sidecar

Nos quatro reports da 0.6.24, cada processo usou uma unica thread de fase para
todas as chamadas do parser e, depois, para a criacao P0-P4 e o
scratch/restauracao do loadout: host `22360`, clientes `9632`, `7636` e
`12408`. Nao houve parser concorrente nem troca de thread durante o rollback.
As chamadas iniciais retornaram `true`, nao alteraram os blocos extras e
conservaram a contagem 1; somente a ultima chamada retornou `false`, escreveu o
bloco P4 e produziu `participant_count_after_parser=5`.

O painel visual executou mais tarde numa thread de UI distinta e foi essa
thread que sofreu a excecao: cliente 1 `19340`, cliente 3 `6716` e host `31564`.
O evento `mission_participant_visual_slot_remapped` aparece na mesma thread da
respectiva excecao e depois de toda a criacao P0-P4. O scratch nativo ja estava
restaurado; a classe atravessa da fase para a UI pelo sidecar protegido por
`SRWLOCK`. Essa separacao confirma o encadeamento parser -> sidecar -> HUD e nao
uma restauracao concorrente do bloco.

Entre a ultima escrita do parser e P4 houve cerca de 32 segundos no host e nos
clientes; entre P4 e o HUD, apenas 0,17 a 0,90 segundo. Por isso o sidecar nao
usa um TTL arbitrario: expirar em 30 segundos descartaria dados validos destes
proprios reports. A validade e delimitada pela sessao e pelo indice logico, e
uma nova saida do parser substitui atomicamente o slot correspondente.

A protecao do parser e o scratch sao `thread_local` para impedir reentrada na
thread de fase; o sidecar compartilhado usa `SRWLOCK` na publicacao/leitura da
thread de UI. Ele e limpo ao criar
ou entrar em uma sala e no desligamento do mod. A classe recuperada permanece
obrigatoriamente em `0..3`, portanto um sidecar antigo pode no pior caso causar
um fallback visual/loadout incorreto, mas nao reabrir a indexacao fora das
quatro classes que causou estes crashes. Nenhuma mudanca adicional de
sincronizacao foi justificada pelos reports.

## Local Mission Harness 0.6.27

O harness reutiliza deliberadamente a rota sintetica do lobby porque ela faz o
EDF5 construir um `net::UserImpl` independente para cada dummy. Duplicar o
objeto do host dentro do vetor final foi descartado: isso repetiria identidade,
controle, nome e estado de replicacao, exatamente a classe de erro que ja foi
observada no primeiro teste de cinco jogadores.

F3 alterna target 3, target 4 e zero. A ativacao exige sala criada pelo processo,
`actual_members == 1`, roster da sala recente e nenhum filler manual. Cada
dummy recebe Ready `+0xC0`, `cm=c1`, `ds=ds` e o clone de PlayerInfo do host. A
reconciliacao `l1/l2` fica pendente desde a ativacao, sem esperar o primeiro
send do canal 0. Nenhuma resposta de gameplay e colocada na fila, portanto os
personagens resultantes permanecem remotos e inertes.

Na copia das colecoes da missao, o gate espera `target+1` objetos e controles
unicos na colecao completa e exatamente um na colecao local. Isso prova que
host+3 percorreu a forma nativa e que host+4 realmente entregou P4 ao builder,
sem alias com P0. No resultado, a escrita local `{phase=1,result=0}` e limitada
aos callers comprovados de `Sync_MissionResult` e exige novamente target 3/4,
um membro real e contagem sintetica exata. Ela nao cria pacote, ack ou peer.

O autoteste isolado valida as tres bordas do F3, ausencia de repeticao ao manter
a tecla, Ready de P1-P4, nome `Harness Dummy 4`, armamento antecipado de l1/l2,
conclusao local do sync e remocao completa ao desligar. O EDF5.exe nao foi
iniciado.

## Spawn de inimigos e resultado em cinco jogadores (0.6.32)

O censo estatico encontrou exatamente 24 chamadas diretas para a rotina comum
de instanciacao em `0x1C1650`. RTTI associa os owners a AlienTrailer, Deiroi,
GeneratorPoll, InsectBase, Monster, Nephila, AntHill e UFOs. A rotina limita a
quantidade viva a 400 e depois aplica `owner+0x290 / owner+0x294`; uma fonte
nula em `owner+0x2B0` tambem impede a criacao. O construtor de GeneratorPoll em
`0x1F872C` usa `participant_count-1` para indexar uma tabela nativa de quatro
entradas, mas o resultado alimenta os timers `+0x1F8/+0x1FC` do owner. Essa
tabela nao escreve a escala `+0x290/+0x294` do subobjeto de spawn e, portanto,
nao prova a origem de uma escala zero.

O hook novo e fail-closed: a instalacao exige a assinatura de `0x1C1650` e que
os 24 `E8 rel32` ainda apontem para ela. O multiplicador e o reparo temporario
so valem para esses retornos confirmados. O reparo exige 5..MaxPlayers,
numerador zero, denominador entre 1 e 1.000.000, fonte presente e memoria
gravavel; a restauracao usa compare/exchange para nao sobrescrever uma mudanca
concorrente.

Nos reports de cinco jogadores, `Sync_MissionResult` de script iniciou em
`0/0`, mas `Exec_Begin` nunca ocorreu. O wrapper registrado em `0x42AC40` chama
`0x42FD20`, e o caller nativo direto em `0x1153EE` fornece o argumento
comprovado `-20000`. A recuperacao 0.6.32 espera 1000 ms, cancela se o caminho
nativo aparecer e, se o stall persistir, chama `Exec_Begin` uma unica vez na
thread `Mission()` em host e clientes reais. O harness F3 e explicitamente
excluido.

### Auditoria de concorrencia 0.6.33

A fila inicial usava tres atomicos independentes. Embora o fluxo observado
seja normalmente single-thread, um segundo `Sync_MissionResult` poderia
sobrescrever tick/geracao antes de falhar o CAS de `pending`, e um
`Exec_Begin` nativo simultaneo poderia cancelar um conjunto parcialmente
publicado. A 0.6.33 serializa publicacao, cancelamento e claim com SRW lock e
incrementa o contador de entrada nativa antes de aguardar esse lock. O caminho
de recuperacao nunca segura o lock enquanto chama codigo do EDF5.

Uma segunda checagem no executavel confirmou os 24 `E8 rel32`, `R8D` como
quantidade, o clamp `0x190`, a fonte em `+0x2B0`, a divisao
`(+0x290 * quantidade) / +0x294` e `mov ecx, 0xFFFFB1E0` imediatamente antes
do call de `MissionResult::Exec_Begin` em `0x1153EE`.

### Guarda de layout 0.6.34

O startup agora valida tambem os blocos semanticos em `0x1C16C6` e
`0x1C16EF`, nao apenas o prologo: preservacao do pedido em `R8D`, clamp 400,
fonte `+0x2B0`, denominador `+0x294`, numerador `+0x290` e as duas divisoes.
O caller `0x1153E9` precisa continuar sendo exatamente
`mov ecx,-20000; call 0x42FD20`.

O verificador offline independente censura qualquer caller extra ou ausente e
confirma o trecho `0x1F910C`: o GeneratorPoll calcula/soma o pedido e chama a
rotina comum antes de consultar o timer derivado da tabela de participantes.
Isso elimina a hipotese de o reparo depender de um ramo posterior que nunca
alcancaria o hook em P5.

### Observabilidade de encerramento 0.6.40

`EmitEnemySpawnSummary` nao omite mais o evento quando o contador e zero. Um
`enemy_spawn_summary` com `calls=0`, `common_spawn_reached=false` e
`confirmed_enemy_path_reached=false` prova que o encerramento foi observado,
mas nenhum caller chegou ao boundary comum. O fixture
`player-spawn-zero-calls-v0639` exige que o analisador preserve essa evidencia
e ainda falhe `--require-enemy-spawn`.

O antigo `mission_result_transition_completed` dependia de sair do lobby
Steam, o que nao prova o retorno a tela da sala quando o lobby continua vivo.
A 0.6.40 encerra o checkpoint no primeiro `HUiRoom::Update` observado depois
que `MissionResultApply` armou o tick de resultado, registra
`completion_signal=room_ui_update` e muda a fase para `room`. O gate nao exige
que a fase textual ja seja `result`: os reports reais mostram clientes presos
em `mission` depois de apply 1 e antes do sync. O caminho nao altera a UI nem
o estado nativo; apenas consome uma vez o tick de resultado. `leave_lobby`
permanece como sinal de fallback separado.

O evento de conclusao inclui contagens de Exec_Begin, sync concluido,
ResolveResult, ApplyResult bem-sucedido e a mascara sanitizada de Items. O
analisador aceita `--require-result-room-return` somente para resultado clear
com o sinal explicito da UI e rejeita conclusoes legadas ou apenas
`leave_lobby`. Se `reward_apply` e `room_return` estiverem presentes, a ordem
tambem e validada e a sala nao pode preceder a aplicacao das recompensas.

### Clamp upstream das tabelas nativas 0.6.41

O censo anterior baseado em `.pdata` encontrou 54 leituras decodificadas de
`mission_state+0x245A0`. Uma segunda varredura integral de `.text`, sem depender
de metadados de unwind, encontrou ainda duas funcoes leaf em `0x8ADCF` e
`0x2D0913`. Ambas executam `mov count; dec; count*3` e usam o resultado para
selecionar um registro de tres dwords. O inventario de escalonamento passa a 56
sites. A outra funcao leaf em `0x11E48E` apenas retorna a contagem real e fica
fora do patch.

O caso `GeneratorPoll` fixa a causa upstream mais direta observada:

- `0x1F872C` le a contagem real e seleciona o perfil `count-1`;
- os multiplicadores calculados gravam `owner+0x1F8/+0x1FC`;
- `0x2DC7C0` compara esses timers e somente `0x2DC82C` chama o virtual de spawn;
- `GeneratorPoll::spawn`, em `0x1F90A0`, chama o boundary comum em `0x1F9120`.

Portanto, lixo/NaN no perfil P5 pode impedir que o hook comum seja alcancado. Os
56 relays preservam as instrucoes e flags originais, limitam apenas o valor
carregado a 4 e deixam `state+0x245A0` intacto em 5..8. Um contador agregado e
uma mascara de 56 bits mostram quais sites foram realmente usados, sem ponteiro,
payload, identidade ou endpoint. O analisador exige essa prova com
`--require-native-participant-scaling-clamp`.

O clamp escolhe o ultimo perfil de dificuldade que existe no jogo; nao aumenta
quantidade de inimigos. O multiplicador opcional permanece em outro modulo,
sob `ExperimentalEnemySpawnMultiplier=false`, com intensidade inativa 1.

### Microexecucao dos 56 relays 0.6.42

O autoteste deixou de conferir apenas o layout emitido. Uma pagina executavel
isolada recebe os mesmos 56 stubs e um thunk Win64 carrega/captura `RAX`,
`R8..R11`, `RBX`, `RDI` e `RFLAGS`. Cada site e chamado com contagem 3, 5 e 8.
O teste exige 3 sem clamp/telemetria e 5/8 reduzidos a 4 com exatamente um hit
e o bit correspondente na mascara de 56 sites.

Tambem sao comparados todos os registradores nao-destino, os bits aritmeticos
de flags e o dword original em `state+0x245A0`. Assim, as quatro variantes de
destino e todas as variantes de base usadas pelo executavel passam pela CPU,
nao apenas por uma inspecao dos bytes. O thunk e as paginas existem somente
durante `EDF5MP_SelfTest`; nenhum microteste roda na inicializacao normal do
EDF5 e nenhuma politica runtime foi alterada.

### Separacao entre armazenamento fixo e colecoes dinamicas do resultado

O corpo completo de `net::MissionResult::Exec_Begin` foi revisado novamente
depois do clamp. Em `0x42FD93..0x42FDCD`, ele zera exatamente quatro qwords em
`state+0x2457C`, `+0x24584`, `+0x2458C` e `+0x24594`. Isso nao e uma nova
rejeicao de P4: sao os quatro acumuladores nativos `Item`, cuja faixa termina
antes do contador de perfis locais em `+0x2459C`. O fold comprovado de P4-P7
depende de manter esse armazenamento com quatro entradas.

Depois, os blocos em `0x430259` e `0x430356` percorrem duas colecoes de handles
com limite calculado como `begin + count * 0x10`. Ambos comparam o cursor com
esse fim dinamico e nao com o imediato 4. Portanto, `Exec_Begin` combina um
array agregado fixo e colecoes dinamicas sem que isso imponha quatro
participantes online. `validate_spawn_result_layout.py` agora fixa as tres
assinaturas e falha fechado se qualquer um desses layouts mudar.

### Censo decodificado de limites no pipeline de resultado

O novo `result_pipeline_scanner.exe` decodifica 2.882 instrucoes nos 12 corpos
comprovados de `Exec_Begin`, begin/poll da named sync, wrappers e implementacoes
de `ResolveResult`/`ApplyResult`, `MissionSync_Res`, `NetGameStatus` e os dois
callers de sync. Em vez de buscar bytes soltos, ele inventaria toda instrucao
com imediato 3, 4 ou 15 e exige os 15 RVAs e encodings exatos conhecidos.

Os onze usos do valor 4 se dividem em seis strides dinamicos de 16 bytes, um
bit de estado, uma reserva inicial de vetor que cresce, um limite fixo dos
quatro acumuladores `Item` e os dois filtros online ja ligados a `MaxPlayers`.
O valor 3 e um shift de divisao do agregado e os tres valores 15 sao constantes
da named sync. Nao existe `and 3`, `and 15` ou outro limite nao classificado
nesses corpos. A suite falha se surgir, desaparecer ou mudar qualquer candidato.

O corpo adicional confirmado na 0.6.43 e `0x42AC40..0x42AC55`. A tabela de
registro o nomeia `int ResultSync_Begin(int)`; ele preserva `ECX`, chama
`Exec_Begin` em `0x42AC48` e retorna o argumento. O unico outro call direto e
`0x1153EE`, no despacho que fornece `-20000`. O scanner e a validacao de startup
agora exigem exatamente esses dois callers. A telemetria de `Exec_Begin`
distingue `mission_script_dispatch`, `result_sync_begin_wrapper` e
`mod_recovery` por RVA sanitizado, sem ponteiro ou payload.

### Contexto local do banner de chat 0.6.47

A rota local de `Chat_Room` em `0x3F16C0` preserva suas duas identidades em
`RSI` e `R12` e as encaminha ao publicador comum no call `0x3F1863`. Dentro de
`0x3F0B70`, a primeira resolucao ocorre em `0x3F0C94..0x3F0CA3` e a segunda em
`0x3F0CB3..0x3F0CC2`; elas fornecem contexto de sala e remetente. A hipotese antiga
de que a segunda identidade zero selecionava a sala publica estava errada e
explica por que o banner pendente so era aceito depois de uma mensagem nativa.

O report `Reports\msg_bug.zip` invalidou a hipotese da 0.6.47. Foram 29
tentativas `room_update_local_self` rejeitadas; a tentativa 30 so foi aceita
por `native_chat_fallback` depois que o usuario digitou. Nesse caller natural,
a primeira identidade nao correspondia a nenhum `UserImpl` registrado. Isso
reclassifica os argumentos: o primeiro e a identidade da sala e o segundo e o
remetente.

### Par sala/remetente do banner de chat 0.6.48

A 0.6.48 passa o lobby ativo na primeira identidade e o SteamID local na
segunda. O `UserImpl` local continua sendo conferido antes da chamada. O
SelfTest recusa o antigo par local/local e exige dois qwords validos e distintos,
respectivamente iguais ao lobby e ao remetente esperados. O caminho segue
direto ao publicador: nao passa por `0x3F16C0` nem `0x44D940` e nao cria trafego
Steam.

O mesmo report mostrou que o quarto argumento de `0x3F0B70` e o texto da
mensagem, nao o nickname. A auditoria runtime antiga foi desativada para nao
fingerprintar o que o usuario digitou. O novo `chat_identity_context` compara
as duas identidades apenas em memoria e persiste flags booleanas, ordinais e
indice de participante; SteamID, lobby ID bruto, nickname e mensagem nunca sao
gravados.

### Publicador local de mensagem de sistema 0.6.49

`Reports\no_msg_2.zip` invalidou tambem o par sala/remetente da 0.6.48: a
tentativa `room_update_lobby_local` foi rejeitada imediatamente, antes de
qualquer texto ser digitado. Esse resultado confirma que `0x3F0B70` nao deve
ser usado para fabricar uma mensagem automatica de jogador, mesmo com as duas
identidades naturais.

O caller em `0x41029C` fornece `Chat_Room` e texto diretamente a `0x3F09D0`.
Esse corpo cria internamente um registro de tipo 1 e o insere na lista local;
nao converge em `0x3F16C0`, `0x3F0B70` ou `0x44D940`. A assinatura validada e
`48 89 54 24 10 55 53 56 57 41 56 48 8B EC 48 83 EC 70 48 C7 45 C0 FE FF FF FF`.

A 0.6.49 usa essa rota somente depois de validar a instancia capturada pela
vtable `0xEBEDA8`. O SelfTest exige exatamente uma chamada com a mesma
instancia e o banner estatico ao entrar e ao criar, nenhuma chamada enquanto a
instancia esta ausente e nenhuma duplicacao. A publicacao nao depende mais de
SteamID, `UserImpl`, estado do editor ou mensagem anterior. O evento registra
somente o RVA, tipo 1, contadores e flags; texto, identidades e ponteiros
continuam fora dos logs.

### Formato visual do banner 0.6.50

O banner estatico passou a usar `***` antes e depois do nome e versao. Esses
caracteres sao ASCII comuns e continuam dentro da mesma `wstring` entregue a
`0x3F09D0`; nenhum campo, tipo, identidade ou caminho de publicacao mudou.

### Ownership real do receive parser 0.6.51

A hipotese de que `manager+0xD0` continha `SharedProperty<UserImpl>` foi
refutada pela desmontagem do registro `0x433BD0`. Ele aloca `0xA8` bytes e
chama `0x435DA0`; a propriedade desse novo objeto e que entra no slot
`route_index*0x10`. O construtor copia o control block do handle original para
`route+0x58` em `0x435E37`. Como o layout do control block conserva o objeto
em `+0x08`, o usuario pode ser recuperado sem guardar identidade ou endereco.

O parser usado pelo pump tambem e um objeto separado. `0x4351F0` recebe o
objeto de rota em RDX e o grava em `parser+0x498` em `0x4352F0`; o pump carrega
o parser de `route+0x88` antes da chamada `0x4339DC`. A cadeia comprovada e:

`parser+0x498 -> route+0x58 -> control+0x08 -> UserImpl`.

O antigo calculo `receive_state-0x88` foi removido. A matriz de recepcao,
lifecycle e escopo incoming agora usam a cadeia real. O SelfTest monta objetos
de rota e parser artificiais com os mesmos offsets e exige resolucao de P4,
alem de detectar rota ausente e identidade duplicada. O scanner independente
confirma os construtores, stores de ownership, call do parser e exatamente um
caller direto para cada construtor.

O loop em `0x45C8E3` examina elementos de oito bytes enquanto o vetor de
recepcao usa slots de `0x10`. Isso ainda nao prova um bug: o owner passado ao
construtor de `UserImpl` pode ser outra classe com offsets coincidentes. A
0.6.51 guarda temporariamente esse owner por usuario e, no lifecycle, registra
somente o booleano `allocator_owner_matches_receive_manager`. Nenhum stride foi
alterado antes dessa comparacao real.

### Update e Finally do resultado 0.6.51

O censo de calls encontrou somente dois callers diretos de `0x430C20`:
`0x42AC9F`, no wrapper de script, e `0x12AA8D`, no consumidor nativo. O retorno
em AL e consumido de forma diferente nesses caminhos, portanto o hook preserva
o `bool` e registra o resultado sem atribuir semantica global.

`0x42F090` e `void` e tambem possui somente dois callers: `0x42AC28` e
`0x12AAA9`. O hook preserva a ABI e mede a origem. O
`result_pipeline_scanner` agora falha se qualquer caller aparecer, sumir ou se
os wrappers mudarem. Esses pontos permitem separar um bloqueio anterior ao
`Update`, dentro dele, antes do `Finally`, no sync nomeado, nas recompensas ou
no retorno da UI.

### Update, motivos do gate e metodo de spawn do GeneratorPoll 0.6.46

O vptr do objeto `GeneratorPoll` usa a vtable `0xEA0E38`. A entrada
`0xEA0ED8`, exatamente `+0xA0`, aponta para `0x1F8B40`; esse update chama o
corpo base `0x2DA720` em `0x1F8B5B` antes de qualquer trabalho especifico. O
corpo base termina em `0x2DA9F4` com tail-jump para `0x2DC7C0`, depois de montar
`RCX=owner+0x400` e `RDX=owner`. A entrada `0xEA0F40`, `+0x108`, aponta para
`0x1F90A0`; a chamada indireta do gate em `0x2DC82C` entra nesse metodo e o
`test al,al` seguinte consome seu retorno. O metodo preserva `RCX` como self,
`RDX` como descritor, consulta `self+0x788` e chama o boundary comum em
`0x1F9120` quando essa dependencia existe.

`GeneratorPollUpdateHook` encaminha os dois argumentos sem inspecionar o
contexto de frame e correlaciona quantos updates chegaram ao metodo de spawn.
`GeneratorPollGateHook` preserva a ABI `void(owner+0x400, owner)`, filtra a
vtable concreta e classifica o desvio exato: cooldown ainda `>=0x1CC` depois
do decremento, quota `+0x00<=0` dentro da janela, metodo retornando AL zero ou
spawn aceito. O evento amostrado `generator_poll_gate_path` registra somente
contadores, escalares pre/pos e bit-patterns dos floats `+0x08`, `+0x1F8` e
`+0x1FC`; nenhum endereco e persistido.

O evento `generator_poll_update_path`, o summary e os breadcrumbs anteriores
aos originais distinguem update ausente, crash dentro do update e cada motivo
do gate. `GeneratorPollSpawnHook` mantem o `RAX` nativo integral e apenas agrega:
chamadas, legibilidade/presenca de `+0x788`, metodos que chegaram ao boundary,
numero de calls comuns e retorno AL verdadeiro/falso. O evento amostrado
`generator_poll_spawn_path` e o `enemy_spawn_summary` declaram explicitamente
que nenhum ponteiro, descritor ou payload foi guardado. O validador offline
fixa os dois slots da vtable, os tres prologos, call base, tail-jump, gate,
boundary e retorno antes da instalacao dos hooks.

### Origem da escala 0.6.38

A desmontagem do configurador comum `0x3AC5F0` separou os dois mecanismos. Em
`0x3AD3DE` o subobjeto de spawn recebe o default fail-closed `0/1`. Somente se
o quarto registro aninhado de configuracao existir, o bloco
`0x3AD3EF..0x3AD52F` copia os inteiros do registro para
`owner+0x290/+0x294`. A fonte em `+0x2B0` e montada a partir da mesma
configuracao, mas por um campo independente.

Logo, zero e um valor nativo possivel antes da configuracao e nao deve ser
atribuido automaticamente ao indice do quinto jogador. O reparo atual continua
experimental e estritamente temporario: ele so pode atuar no boundary comum,
com caller confirmado, pedido positivo, fonte presente, denominador plausivel
e 5..MaxPlayers; o valor original e registrado e restaurado depois da chamada.
O proximo report real dira se o boundary sequer foi alcancado e, se foi, qual
par de escala chegou nele. O multiplicador permanece apenas infraestrutura
opcional. `ExperimentalEnemySpawnMultiplier=false` e um segundo gate alem do
valor `EnemySpawnMultiplier=1`; assim, mudar apenas a intensidade nao altera o
MultiSlot em desenvolvimento.

O validador offline agora fixa os tres blocos de configuracao, a tabela de
timer separada e os 24 callers. `tools/find_member_accesses.py` tambem permite
enumerar acessos decodificados a offsets de membros sem carregar o executavel.

Os 24 callers formam tres familias de ABI, todas com `RCX=owner`,
`RDX=descriptor` e `R8D=requested_count` no boundary comum:

- onze caminhos de simulacao consultam o descritor com `0x3BCB00` e entregam
  uma ou duas parcelas inteiras do pedido;
- onze caminhos espelhados/serializados validam a leitura com `0x3BE480` e,
  quando necessario, materializam o descritor com `0x405A40` antes do call;
- os dois caminhos especiais `0x243CAD` e `0x245F8F` somam tres parcelas e
  aplicam primeiro um limite local de 50; o limite comum de 400 continua sendo
  aplicado depois.

Nos caminhos espelhados, falha do helper pula o spawn. Nos especiais, pedido
zero tambem pula o call. Os demais chegam ao boundary, que ainda rejeita fonte
nula e resultado escalado zero. Nao apareceu indexacao de participante na
montagem de `R8D`; a unica indexacao `participant_count-1` comprovada no
`GeneratorPoll` ocorre depois do call no fluxo de update e alimenta o timer.

### Reset por geração 0.6.37

O replay dos reports reais 0.6.31 posiciona o bloqueio depois de
`mission_result_apply(1)` e no primeiro `Sync_MissionResult(script, 0/0)`, com
`Exec_Begin=0` em host e clientes. O hook atual arma a recuperação dentro desse
begin, antes do poll repetido observado até 30 segundos.

Uma nova fase na mesma sala agora chama
`ResetMissionResultExecRecoveryState` sob o lock exclusivo. A operação descarta
fila, tick e geração anteriores e zera call/attempt/cancel como um único estado
de geração. O SelfTest injeta uma fila da geração 4, força o gap normal de fase
e exige geração 5 com todos os campos zerados. O analisador aceita o novo evento
sanitizado `mission_result_exec_recovery_generation_reset` somente quando
`stale_pending_discarded` e `queue_cleared` são verdadeiros.

### Cancelamento nativo sequencial 0.6.36

O estado lógico da fila de recuperação (`pending`, tick e geração) agora é
limpo por uma única rotina chamada somente sob
`g_mission_result_exec_recovery_lock`. O SelfTest runtime enfileira a
recuperação, chama o wrapper nativo antes do grace period e exige cancelamento
único, uma chamada original aceita, zero tentativas de fallback e os três
campos zerados. Em seguida confirma que o mesmo sync não pode reenfileirar e
que um poll posterior não duplica `Exec_Begin`.

`analyze_player_controls.py` modela agora `Exec_Begin` e a recuperação com
registros nomeados que preservam ordem e geração. O fixture positivo exige
`queued -> cancelled -> Exec_Begin` com argumento preservado e sem fallback;
o negativo contém cancelamento seguido por duas chamadas e `applied`, e só
passa na suíte quando o analisador rejeita ambas as duplicações.

### SelfTest runtime 0.6.35

O wrapper de ABI agora apenas resolve o return address e delega ao mesmo
`DispatchEnemySpawn` usado pelo SelfTest. Com participante 5, caller confirmado,
pedido 10, multiplicador 2, escala `0/4` e fonte valida, a funcao original falsa
precisa receber 20 enquanto observa numerador 4. Ao retornar, o owner precisa
conter zero novamente e os agregados precisam registrar um call, um reparo e
nenhuma falha.

`RestoreEnemySpawnScale` e testado separadamente com valor concorrente 7. O CAS
espera 4, falha sem escrever e preserva 7, cobrindo a regra que impede o mod de
apagar mudancas nativas ou de outro hook.

## Auditoria real de cinco jogadores e telemetria 0.6.53

Os cinco reports da 0.6.52 completaram duas fases sem crash e fecharam a
propriedade local P0-P4 exatamente uma vez entre server e quatro clientes. O
fan-out de cada processo continha quatro rotas unicas e a mascara total de
destinos era sempre `0x1f` menos o bit local. A 0.6.53 usa essa propriedade
local como fallback somente quando ha um unico bit; owner ausente deixa de
transformar um fan-out correto em warning sem aceitar casos ambiguos.

O vetor de recepcao real e remoto e prealocado: slots vazios e a ausencia do
participante local sao normais. A auditoria passa a comparar com
`participant_mask & ~local_mask`, separa empty de unresolved e nao exige
`runtime_user_count == route_count`. A cadeia do parser permanece valida, mas
seu lifetime nao alcancou o dispatcher; atribuicao incoming por participante
continua um gate aberto.

`ApplyResult 0x3E3160` chama `0x199D50` antes de decidir seu retorno auxiliar.
Nos dez eventos reais o retorno foi false, embora Items `0x1f`, sync, reward e
retorno estivessem completos. O contador e o analisador agora medem
`call_completed`; o valor nativo e preservado apenas como dado semantico. Os
warnings do primeiro GeneratorPoll update e de checkpoints de resultado que
depois concluiram tambem foram reclassificados.

Evidencia completa:
[`docs/technical-research/09-TESTE-REAL-5-JOGADORES-2026-08-31.md`](docs/technical-research/09-TESTE-REAL-5-JOGADORES-2026-08-31.md).
