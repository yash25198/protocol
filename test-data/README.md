# Bitcoin Test Data

Stores the first 800k bitcoin block headers in git-lfs

## Requirements
- [uv](https://docs.astral.sh/uv/getting-started/installation/)

## Run 
Downloads headers, blocks, as well as some bitcoin cash headers (to test fork choice)
```
uv run get_bitcoin_data.py
```