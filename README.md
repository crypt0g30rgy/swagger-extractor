## About

A tool to extract a swagger file endpoints.

## Installation && Usage

to use the tool just clone the repo 

```bash
git clone https://github.com/crypt0g30rgy/swagger-extractor
```

then do the following to get all possible flags;

```bash
python3 swagger_extractor.py
```

or for all endpoints in a txt file to feed to burp or other tools

```bash
python3 swagger_extractor.py -e
```

or for all endpoints and methods in a txt file

```bash
python3 swagger_extractor.py -a
```