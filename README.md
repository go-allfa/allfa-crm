# Allfa CRM · Kanban de Vendas

Quadro kanban simples para o time de vendas acompanhar contatos e o status das negociações.

Colunas: **Novo contato → Em qualificação → Proposta enviada → Em negociação → Fechado (ganho) / Perdido**

## Funcionalidades

- Cadastro de contato com **nome, telefone, LinkedIn, loja e como foi feito o contato**
  (LinkedIn, WhatsApp, Telefone, E-mail, Indicação, Visita presencial, Evento, Outro), além de observações.
- Arrastar e soltar cartões entre colunas (ou trocar o status pelo formulário, útil no celular).
- Busca por nome/loja/telefone e filtro por forma de contato.
- Histórico por contato (quem criou, quem mudou o status e quando).
- Login individual por pessoa do time; administradores cadastram e desativam usuários pela tela **Usuários**.

## Segurança

- **Sem cadastro público**: só entra quem um administrador cadastrar.
- Senhas com hash **scrypt** + salt; comparação em tempo constante.
- Sessão em cookie `HttpOnly`, `SameSite=Strict` e `Secure` (HTTPS), expira em 12h; o token fica com hash no banco.
- Proteção **CSRF** (token por sessão exigido em toda alteração).
- **Limite de tentativas** de login (5 a cada 15 min por IP + e-mail).
- Cabeçalhos de segurança: CSP restritiva (sem scripts inline), `X-Frame-Options: DENY`, HSTS, `nosniff`, `no-referrer`.
- Validação de entrada no servidor (tamanhos, telefone; LinkedIn aceita apenas `https://*.linkedin.com`).
- O front-end nunca usa `innerHTML` com dados do usuário (evita XSS); SQL sempre parametrizado.
- Container roda como usuário não-root; página marcada como `noindex`.
- Trocar a senha encerra as outras sessões; desativar um usuário derruba as sessões dele na hora.

## Stack

Node.js 22 + Express 5 + SQLite embutido do Node (`node:sqlite`). Única dependência: `express`.
Front-end em HTML/CSS/JS puro, sem etapa de build.

## Rodando localmente

```bash
npm install
cp .env.example .env              # COOKIE_SECURE=false para rodar sem HTTPS
npm run create-user -- --admin    # cria o primeiro administrador (pede e-mail, nome e senha)
npm start                         # http://127.0.0.1:3000
```

Testes: `npm test`

## Publicando para o time (produção)

Recomendado: Docker atrás de um proxy reverso com HTTPS (Caddy, Nginx, Traefik, Cloudflare Tunnel…).

```bash
docker compose up -d --build
docker compose exec crm node scripts/create-user.js --admin   # primeiro admin
```

O `docker-compose.yml` publica a porta **apenas em 127.0.0.1:3000**; exponha para fora somente via proxy HTTPS.
Exemplo com Caddy (certificado automático):

```
crm.suaempresa.com.br {
    reverse_proxy 127.0.0.1:3000
}
```

Recomendações extras para manter o acesso só interno:

- Restrinja o acesso por VPN/rede da empresa, por IP no proxy/firewall, ou coloque um túnel com SSO
  (ex.: Cloudflare Access, Tailscale) na frente da aplicação.
- Faça backup periódico do volume `crm-data` (arquivo `crm.sqlite`).

### Variáveis de ambiente

| Variável        | Padrão              | Descrição |
|-----------------|---------------------|-----------|
| `PORT`          | `3000`              | Porta HTTP |
| `HOST`          | `127.0.0.1`         | Interface de rede (`0.0.0.0` dentro do Docker) |
| `DB_PATH`       | `./data/crm.sqlite` | Arquivo do banco |
| `COOKIE_SECURE` | `true`              | `false` somente em desenvolvimento sem HTTPS |
| `TRUST_PROXY`   | vazio               | Nº de proxies à frente (ex.: `1`), para identificar o IP real no limite de login |

## Gerenciando usuários

- Pela tela: botão **Usuários** (visível para administradores) → adicionar / desativar / reativar.
- Pelo terminal: `npm run create-user` (ou `npm run create-user -- --admin`). Se o e-mail já existir, a senha é redefinida.
