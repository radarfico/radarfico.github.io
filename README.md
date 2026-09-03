# Radar FICO

Aplicação independente para acompanhamento de frentes de serviço e riscos em campo.

## Publicação

O site é publicado em `https://radarfico.github.io/` pelo GitHub Pages.

## Acesso

O painel operacional, histórico e administração exigem autenticação. As permissões por empresa continuam sendo aplicadas na API dedicada `radarfico-api`; o código do site não carrega arquivos, páginas ou dados do CCO/Central FICO.

## Operação da API

O diretório `worker/` contém o Worker exclusivo do Radar. Ele utiliza a base de dados existente apenas para preservar o histórico e expõe somente as rotas do Radar.
