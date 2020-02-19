eval "$(docker-machine env dev)"

# build and deploy project
docker-compose down
docker-compose build --force-rm --pull --parallel
docker-compose up -d
docker-compose run web /usr/local/bin/python create_db.py
docker-machine ip dev

### curl tests
curl -X GET http://$(docker-machine ip dev):80/
