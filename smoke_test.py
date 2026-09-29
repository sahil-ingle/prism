from prism.detector import detect_ioc

samples = [
    "8.8.8.8",
    "example.com",
    "https://example.com/login",
    "44d88612fea8a8f36de82e1278abb02f",
    "a" * 40,
    "a" * 64,
]

for sample in samples:
    ioc = detect_ioc(sample)
    print(f"{sample[:30]:30} -> {ioc.type.value}")
