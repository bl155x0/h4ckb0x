all:
	docker build -t h4ckb0x .
clean:
	docker builder prune
