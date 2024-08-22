from pydantic import BaseModel, constr, conint


class BlockModel(BaseModel):
    index: int
    previous_hash: constr(min_length=64, max_length=64)
    timestamp: conint(ge=0)
    data: str
    nonce: int
    path: str
    file_name: str
    pubkey: constr(min_length=1, max_length=128)
    hash_pubkey: constr(min_length=1, max_length=128)
    data_sign: constr(min_length=64, max_length=64)
    hash: constr(min_length=64, max_length=64)
