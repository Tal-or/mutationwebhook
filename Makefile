IMAGE_NAME ?= quay.io/titzhak/mutationwebhook

# Default target
all: build push

# Build the Docker image
build:
	docker build -t $(IMAGE_NAME) .

# Push the Docker image to the registry
push:
	docker push $(IMAGE_NAME)

# Clean up the image (optional, for cleanup purposes)
clean:
	docker rmi $(IMAGE_NAME)