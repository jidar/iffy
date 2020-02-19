# Start docker, set machine up
sudo systemctl start docker
docker-machine rm dev
docker-machine create -d virtualbox dev
eval "$(docker-machine env dev)"

# build and deploy project
docker-compose up --build -d

# create DB table
docker-compose run web /usr/local/bin/python create_db.py

### curl tests
curl -X GET http://$(docker-machine ip dev):80/api
