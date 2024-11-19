all:
	docker build -t h4ckb0x .
new:
	docker build --no-cache -t h4ckb0x .
clean:
	docker builder prune
