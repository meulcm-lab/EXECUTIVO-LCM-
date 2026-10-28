import base64
import hmac
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

ROOT = Path(__file__).resolve().parent
app = FastAPI(title="Executivo LCM — Auditoria CV CRM")
security = HTTPBasic()
_CACHE: dict[str, tuple[float, Any]] = {}
CACHE_TTL = int(os.getenv("CVCRM_CACHE_TTL", "600"))
DEFAULT_CONDITIONS_ENDPOINT = "/api/v1/comercial/reservas/condicao-pagamentos"


def env_required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise HTTPException(status_code=503, detail=f"Configure a variável {name} no serviço de hospedagem.")
    return value


def check_dashboard_login(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    username = os.getenv("AUDIT_USER", "")
    password = os.getenv("AUDIT_PASSWORD", "")
    if not username or not password:
        raise HTTPException(status_code=503, detail="Configure AUDIT_USER e AUDIT_PASSWORD no serviço de hospedagem.")
    ok_user = hmac.compare_digest(credentials.username.encode("utf-8"), username.encode("utf-8"))
    ok_pass = hmac.compare_digest(credentials.password.encode("utf-8"), password.encode("utf-8"))
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, detail="Acesso não autorizado à auditoria.", headers={"WWW-Authenticate": "Basic"})
    return credentials.username


def norm(value: Any) -> str:
    import unicodedata
    return "".join(c for c in unicodedata.normalize("NFKD", str(value or "")).upper() if not unicodedata.combining(c))


def compact(value: Any) -> str:
    import re
    return re.sub(r"[^a-z0-9]", "", norm(value).lower())


def nested(row: dict, *keys: str) -> Any:
    current: Any = row
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def pick(row: dict, names: list[str], default: Any = "") -> Any:
    if not isinstance(row, dict):
        return default
    indexed = {compact(k): v for k, v in row.items()}
    for name in names:
        key = compact(name)
        if key in indexed and indexed[key] not in (None, ""):
            return indexed[key]
    return default


def number(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, dict):
        value = pick(value, ["valor", "value", "total"], 0)
    s = str(value or "").strip().replace("R$", "").replace("%", "").replace(" ", "")
    if not s:
        return 0.0
    if "," in s and "." in s:
        s = s.replace(".", "").replace(",", ".")
    elif "," in s:
        s = s.replace(",", ".")
    try:
        return float(s)
    except (ValueError, TypeError):
        return 0.0


def clean(value: Any) -> str:
    if isinstance(value, dict):
        return str(pick(value, ["nome", "descricao", "titulo", "situacao", "nomefantasia", "razaosocial"], "") or "")
    if value is None:
        return ""
    return str(value).strip()


def api_config() -> tuple[str, str, str]:
    base = env_required("CVCRM_DOMINIO").rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    email = env_required("CVCRM_EMAIL")
    token = env_required("CVCRM_TOKEN")
    return base, email, token


def cvcrm_get(endpoint: str, email: str, token: str, params: dict | None = None, timeout: int = 35):
    base, _, _ = api_config()
    url = base + "/" + endpoint.lstrip("/")
    headers = {"email": email, "token": token, "Accept": "application/json"}
    last = None
    for attempt in range(4):
        response = requests.get(url, headers=headers, params=params or {}, timeout=timeout)
        last = response
        if response.status_code != 429:
            break
        retry = response.headers.get("Retry-After", "")
        try:
            wait = float(retry) if retry else min(3 * (2 ** attempt), 20)
        except (TypeError, ValueError):
            wait = min(3 * (2 ** attempt), 20)
        time.sleep(max(1, min(wait, 25)))
    if last is None:
        raise HTTPException(status_code=502, detail="O CV CRM não respondeu à consulta.")
    if last.status_code == 401:
        raise HTTPException(status_code=502, detail="O CV CRM recusou a autenticação. Confira CVCRM_EMAIL e CVCRM_TOKEN no servidor.")
    if last.status_code == 403:
        raise HTTPException(status_code=502, detail="O token do CV CRM não tem permissão para consultar esse recurso.")
    if last.status_code == 429:
        raise HTTPException(status_code=503, detail="O CV CRM está limitando as consultas (HTTP 429). Aguarde alguns minutos e tente novamente.")
    if last.status_code == 204:
        return {"dados": [], "total_de_paginas": 1}
    last.raise_for_status()
    try:
        return last.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="O CV CRM retornou uma resposta que não é JSON.") from exc


def fetch_all(endpoint: str, email: str, token: str) -> list[dict]:
    rows: list[dict] = []
    page = 1
    pages = 1
    while page <= pages:
        payload = cvcrm_get(endpoint, email, token, {"pagina": page, "registros_por_pagina": 500})
        data = payload.get("dados", []) if isinstance(payload, dict) else []
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            raise HTTPException(status_code=502, detail=f"Formato inesperado retornado por {endpoint}.")
        rows.extend(item for item in data if isinstance(item, dict))
        try:
            pages = max(page, int(payload.get("total_de_paginas", page) or page)) if isinstance(payload, dict) else page
        except (TypeError, ValueError):
            pages = page
        if not data:
            break
        page += 1
        if page <= pages:
            time.sleep(0.2)
    return rows


def unit_id(row: dict) -> str:
    value = pick(row, ["idunidade", "id_unidade", "unidade_id", "idunidade_cv", "id_unidade_cv", "id_unidade_int", "codigo_unidade"], "")
    if not value:
        nested_unit = row.get("unidade")
        if isinstance(nested_unit, dict):
            value = pick(nested_unit, ["id", "idunidade", "id_unidade", "codigo"], "")
    return clean(value)


def project_name(row: dict) -> str:
    value = pick(row, ["empreendimento", "nomeempreendimento", "nome_empreendimento", "empreendimento_nome"], "")
    if isinstance(value, dict):
        value = pick(value, ["nome", "nomeempreendimento", "nome_empreendimento", "descricao"], "")
    return clean(value)


def status_text(row: dict) -> str:
    value = pick(row, ["situacao", "situação", "status", "situacao_unidade", "status_unidade", "disponibilidade", "nome_situacao", "status_reserva", "situacao_reserva"], "")
    if isinstance(value, dict):
        value = pick(value, ["situacao", "status", "nome", "descricao"], "")
    return norm(value).strip()


def is_sold(value: str) -> bool:
    return any(term in value for term in [
        "VENDID", "CONTRATO ASSINADO", "ENVIADO PARA UAU", "BOLETO/PIX", "BOLETO PIX",
        "AGUARDANDO ASSINATURA INTERNA", "CONTRATO ASSINADO POR TODOS", "FATURAD", "PODE FATURAR"
    ])


def series_amount(item: dict) -> float:
    for field in ["subtotal", "subtotalComJuros", "subtotal_com_juros", "valor_total", "total"]:
        raw = item.get(field)
        if raw not in (None, "") and number(raw) > 0:
            return number(raw)
    value = pick(item, ["valor", "valorComJuros", "valor_com_juros", "valor_parcela", "valorparcela"], 0)
    quantity = pick(item, ["quantidade", "qtd", "numero_parcelas", "numero_parcelas_total"], 1)
    return number(value) * max(number(quantity), 1)


def payment_summary(row: dict) -> dict:
    raw = row.get("condicao", [])
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = []
    if not raw:
        conditions = row.get("condicoes", {})
        if isinstance(conditions, str):
            try:
                conditions = json.loads(conditions)
            except Exception:
                conditions = {}
        raw = conditions.get("series", row.get("series", row.get("plano_pagamento", []))) if isinstance(conditions, dict) else []
    if isinstance(raw, dict):
        raw = list(raw.values())
    if not isinstance(raw, list):
        raw = []
    amounts: dict[str, float] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        label = norm(pick(item, ["serie", "nome", "descricao", "nome_serie", "tipo"], ""))
        amounts[label] = amounts.get(label, 0.0) + series_amount(item)

    def amount_for(*names: str) -> float:
        return sum(value for label, value in amounts.items() if any(norm(n) in label for n in names))

    fgts = amount_for("FGTS") or number(row.get("valor_fgts"))
    subsidy = amount_for("SUBSIDIO", "VALOR SUBSIDIO MUNICIPAL") or number(row.get("valor_subsidio"))
    financing = amount_for("FINANCIAMENTO") or number(row.get("valor_financiamento"))
    adpremiada = amount_for("ADIMPLENCIA PREMIADA") or number(row.get("valor_adpremiada")) or number(row.get("valor_adimplencia_premiada"))
    housing = amount_for("CHEQUE MORADIA") or number(row.get("valor_ch_moradia")) or number(row.get("valor_cheque_moradia"))
    prosoluto_names = ["PRO SOLUTO", "PRO-SOLUTO", "PROSOLUTO", "MENSAIS", "MENSAL"]
    prosoluto = sum(value for label, value in amounts.items() if any(norm(n) in label for n in prosoluto_names))
    prosoluto = prosoluto or number(row.get("valor_pro_soluto")) or number(row.get("valor_prosoluto"))
    return {
        "FGTS": fgts, "Subsídio": subsidy, "Financiamento": financing,
        "Total Financiado": fgts + subsidy + financing,
        "AdPremiada": adpremiada, "Ch_Moradia": housing, "Pró-Soluto": prosoluto,
        "_has_conditions": bool(raw) or any([fgts, subsidy, financing, adpremiada, housing, prosoluto])
    }


def series_description(row: dict) -> str:
    raw = row.get("condicao", [])
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = []
    if not raw:
        conditions = row.get("condicoes", {})
        if isinstance(conditions, str):
            try:
                conditions = json.loads(conditions)
            except Exception:
                conditions = {}
        raw = conditions.get("series", row.get("series", row.get("plano_pagamento", []))) if isinstance(conditions, dict) else []
    if isinstance(raw, dict):
        raw = list(raw.values())
    if not isinstance(raw, list):
        return ""
    descriptions = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        label = clean(pick(item, ["serie", "nome", "descricao", "nome_serie", "tipo"], ""))
        amount = series_amount(item)
        quantity = pick(item, ["quantidade", "qtd", "numero_parcelas", "numero_parcelas_total"], "")
        if label:
            detail = f"{label}: {amount:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
            if quantity not in (None, "") and number(quantity) > 1:
                detail += f" ({clean(quantity)} parcelas)"
            descriptions.append(detail)
    return " | ".join(descriptions)


def fetch_conditions(reservation_id: str, endpoint: str, email: str, token: str) -> list[dict]:
    payload = cvcrm_get(endpoint, email, token, {"idreserva": reservation_id, "pagina": 1, "registros_por_pagina": 500}, timeout=18)
    data = payload.get("dados", []) if isinstance(payload, dict) else []
    if isinstance(data, dict):
        data = [data]
    out = []
    for record in data if isinstance(data, list) else []:
        if not isinstance(record, dict):
            continue
        cond = record.get("condicao", record.get("condicoes", []))
        if isinstance(cond, str):
            try:
                cond = json.loads(cond)
            except Exception:
                cond = []
        if isinstance(cond, dict):
            cond = list(cond.values())
        if isinstance(cond, list):
            for item in cond:
                if isinstance(item, dict):
                    out.append(item)
    return out


def enrich_with_conditions(row: dict, series: list[dict]) -> dict:
    if not series:
        return row
    merged = dict(row)
    merged["condicao"] = series
    return {**row, **payment_summary(merged)}


def build_rows(units: list[dict], sales: list[dict], include_conditions: bool, email: str, token: str) -> list[dict]:
    sale_by_unit: dict[str, list[dict]] = {}
    for sale in sales:
        uid = unit_id(sale)
        if uid:
            sale_by_unit.setdefault(uid, []).append(sale)

    # Se o ID da unidade não existir no payload da reserva, tenta número + empreendimento.
    sale_by_name: dict[tuple[str, str], list[dict]] = {}
    for sale in sales:
        uname = clean(pick(sale, ["nome_unidade", "unidade", "apartamento", "numero_unidade", "nome"], ""))
        emp = project_name(sale)
        if uname:
            sale_by_name.setdefault((compact(emp), compact(uname)), []).append(sale)

    candidates = []
    for unit in units:
        uid = unit_id(unit)
        emp = project_name(unit)
        uname = clean(pick(unit, ["nome", "unidade", "nome_unidade", "apartamento", "numero_unidade", "codigo_unidade"], ""))
        unit_status = status_text(unit)
        matches = sale_by_unit.get(uid, []) if uid else []
        if emp and matches:
            project_matches = [s for s in matches if not project_name(s) or compact(project_name(s)) == compact(emp)]
            if project_matches:
                matches = project_matches
        if not matches and uname:
            matches = sale_by_name.get((compact(emp), compact(uname)), [])
        matches = [s for s in matches if is_sold(status_text(s))] or matches
        sale = matches[-1] if matches else {}
        sale_status = status_text(sale) if sale else ""
        if not (is_sold(unit_status) or is_sold(sale_status)):
            continue

        titular = sale.get("titular", {}) if isinstance(sale.get("titular"), dict) else {}
        imobiliaria = sale.get("imobiliaria", {}) if isinstance(sale.get("imobiliaria"), dict) else {}
        corretor = sale.get("corretor", {}) if isinstance(sale.get("corretor"), dict) else {}
        client = clean(pick(sale, ["cliente", "nome_cliente", "titular_nome"], "")) or clean(pick(titular, ["nome", "cliente"], ""))
        agency = clean(pick(sale, ["nome_imobiliaria", "imobiliaria_nome"], "")) or clean(pick(imobiliaria, ["nome", "nomefantasia", "razaosocial"], "")) or clean(pick(corretor, ["imobiliaria", "nome_imobiliaria"], ""))
        if not agency:
            agency = clean(sale.get("imobiliaria", ""))
        renda = number(pick(sale, ["renda", "renda_familiar"], pick(titular, ["renda_familiar", "renda"], 0)))
        contract = number(pick(sale, ["valor_venda", "valor_contrato", "valor_total", "vgv", "valor"], pick(unit, ["valor_vgv", "vgv", "valor_unidade", "valor_venda", "valor_tabela", "valor"], 0)))
        pay = payment_summary(sale)
        reservation_id = clean(pick(sale, ["idreserva_cv", "idreserva", "id_reserva", "idproposta_cv", "idproposta", "id"], ""))
        candidates.append({
            "Cliente": client, "Empreendimento": emp or project_name(sale), "Imobiliária": agency,
            "Data da Venda": clean(pick(sale, ["data_venda", "datavenda", "data_da_venda", "data_contrato", "data_assinatura", "dataassinatura", "data_reserva", "datareserva", "created_at", "createdAt", "data_criacao", "datacriacao"], "")),
            "Séries": series_description(sale),
            "Bloco": clean(pick(unit, ["bloco", "nome_bloco", "bloco_nome"], "")),
            "Unidade": uname or uid, "M²": number(pick(unit, ["area_privativa", "m2", "area", "area_util"], 0)),
            "Etapa": clean(pick(unit, ["etapa", "nome_etapa"], "")) or clean(pick(sale, ["etapa", "status_reserva", "situacao_reserva", "situacao", "status"], "")),
            "Renda Familiar": renda, "Valor Total": contract,
            "Valor Líquido": contract - pay["AdPremiada"] - pay["Ch_Moradia"],
            "FGTS": pay["FGTS"], "Subsídio": pay["Subsídio"], "Financiamento": pay["Financiamento"],
            "Total Financiado": pay["Total Financiado"], "AdPremiada": pay["AdPremiada"],
            "Ch_Moradia": pay["Ch_Moradia"], "Pró-Soluto": pay["Pró-Soluto"],
            "Risco": (pay["Pró-Soluto"] / contract * 100) if contract > 0 else 0,
            "_reservation_id": reservation_id, "_has_conditions": pay["_has_conditions"],
            "_raw_status": unit_status or sale_status
        })

    if include_conditions:
        endpoint = os.getenv("CVCRM_ENDPOINT_CONDICOES", DEFAULT_CONDITIONS_ENDPOINT).strip()
        targets = [r for r in candidates if r.get("_reservation_id") and not r.get("_has_conditions")]
        # Evita disparar uma avalanche de requisições no primeiro carregamento.
        # O limite é explícito; o botão de atualizar pode ser usado novamente depois.
        targets = targets[:300]
        def load_one(item):
            return item, fetch_conditions(item["_reservation_id"], endpoint, email, token)
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(load_one, item) for item in targets]
            for future in as_completed(futures):
                try:
                    item, series = future.result()
                    if series:
                        new = enrich_with_conditions(item, series)
                        item["Séries"] = series_description({"condicao": series}) or item.get("Séries", "")
                        for key in ["FGTS", "Subsídio", "Financiamento", "Total Financiado", "AdPremiada", "Ch_Moradia", "Pró-Soluto", "Risco", "Valor Líquido"]:
                            item[key] = new.get(key, item.get(key))
                        item["_has_conditions"] = True
                except Exception:
                    # Mantém a linha e os valores nativos se o endpoint secundário falhar.
                    continue

    public_rows = []
    for row in candidates:
        public_rows.append({k: v for k, v in row.items() if not k.startswith("_")})
    return public_rows


def get_audit_data(include_conditions: bool, refresh: bool = False) -> dict:
    key = "detailed" if include_conditions else "basic"
    now = time.time()
    if not refresh and key in _CACHE and now - _CACHE[key][0] < CACHE_TTL:
        return _CACHE[key][1]
    base, email, token = api_config()
    sales_endpoint = os.getenv("CVCRM_ENDPOINT_VENDAS", "/api/v1/cvdw/reservas").strip()
    units_endpoint = os.getenv("CVCRM_ENDPOINT_UNIDADES", "/api/v1/cvdw/unidades").strip()
    sales = fetch_all(sales_endpoint, email, token)
    units = fetch_all(units_endpoint, email, token)
    rows = build_rows(units, sales, include_conditions, email, token)
    result = {
        "rows": rows,
        "source": "CV CRM",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "units_received": len(units),
        "reservations_received": len(sales),
        "conditions_requested": include_conditions
    }
    _CACHE[key] = (now, result)
    return result


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "executivo-lcm-auditoria"}


@app.get("/api/auditoria")
def audit(
    include_conditions: bool = Query(False),
    refresh: bool = Query(False),
    _user: str = Depends(check_dashboard_login),
):
    try:
        return get_audit_data(include_conditions, refresh)
    except HTTPException:
        raise
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Falha ao consultar o CV CRM: {exc.__class__.__name__}.") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Não foi possível montar a auditoria do CV CRM ({exc.__class__.__name__}).") from exc


@app.get("/")
def home():
    return FileResponse(ROOT / "index.html", media_type="text/html")


@app.get("/perfil_compradores.html")
def compradores():
    return FileResponse(ROOT / "perfil_compradores.html", media_type="text/html")


@app.get("/perfil_compradores_dados.gz.b64")
def compradores_data():
    return FileResponse(ROOT / "perfil_compradores_dados.gz.b64", media_type="text/plain")


@app.get("/{path:path}")
def static_files(path: str):
    candidate = (ROOT / path).resolve()
    if not str(candidate).startswith(str(ROOT.resolve())) or not candidate.is_file():
        raise HTTPException(status_code=404, detail="Arquivo não encontrado.")
    return FileResponse(candidate)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
