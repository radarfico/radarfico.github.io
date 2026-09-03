# Radar FICO — sistema visual

## Direção

Interface operacional-industrial: alto contraste, leitura rápida e acabamento sóbrio. O azul-marinho estrutura a navegação, o ciano identifica informação, o laranja indica ação e o vermelho fica reservado a criticidade.

## Tipografia

- Barlow Condensed: títulos, indicadores e números operacionais.
- DM Sans: textos, campos e controles.
- Texto funcional mínimo: 11 px; conteúdo principal: 12–16 px.
- Números de KPI usam algarismos tabulares.

## Espaçamento e superfícies

- Escala: 4, 8, 12, 16, 24 e 32 px.
- Raio interno: 4 px; cartões e diálogos: 8 px.
- Sombras recebem tonalidade azul-marinho e devem indicar hierarquia, nunca decoração.
- Foco de teclado: halo ciano de 3 px.

## Responsividade

- Desktop: mapa e painel lateral em duas colunas.
- Até 1100 px: painel abaixo do mapa.
- Até 896 px: KPIs em três colunas e login em duas colunas.
- Até 700 px: KPIs em duas colunas, formulários em uma coluna e comandos do mapa roláveis.

## Movimento

- Transições entre 160 e 360 ms.
- Movimento apenas com `transform` e `opacity`.
- `prefers-reduced-motion` sempre respeitado.
