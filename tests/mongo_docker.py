import subprocess

def run_command(command):
    try:
        subprocess.run(command, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")

def setup_mongodb_container(image="mongo", container_name="test-mongodb", port="27017", username="testuser", password="testpass"):
    # Pull the MongoDB image
    run_command(f"docker pull {image}")

    # Run the MongoDB container with environment variables for user credentials
    run_command(f"docker run --name {container_name} -d -p {port}:{port} "
                f"-e MONGO_INITDB_ROOT_USERNAME={username} -e MONGO_INITDB_ROOT_PASSWORD={password} "
                f"-e MONGO_INITDB_DATABASE=test "
                f"{image}")


def delete_mongodb_container(container_name="test-mongodb"):
    # Stop the MongoDB container
    run_command(f"docker stop {container_name}")

    # Remove the MongoDB container
    run_command(f"docker rm {container_name}")

if __name__ == "__main__":
    # Setup MongoDB container
    setup_mongodb_container()

    # delete_mongodb_container()
