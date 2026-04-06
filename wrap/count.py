import tiktoken
enc = tiktoken.encoding_for_model("gpt-5")
file_path = "snort_output.txt"
with open(file_path, 'r', encoding='utf-8') as f:
    text = f.read()

tokens = enc.encode(text)
token_count = len(tokens)
print(f"文本长度: {len(text)} 字符")
print(f"Token数量: {token_count} 个")
