#!/bin/bash

BASE_URL="http://localhost:8080/sample-jwt-web"
HEADERS_FILE="response-headers.txt"

if [ -f $HEADERS_FILE ] ; then
  rm $HEADERS_FILE
fi

curl --dump-header $HEADERS_FILE \
  -H 'Content-Type: application/json' \
  -d '{ "username": "bob", "password": "bob"}' \
  $BASE_URL/login

TOKEN=$(grep Authorization $HEADERS_FILE | cut -d' ' -f3)

echo "Readed JWT Token: $TOKEN"

echo "Reading pets:"

curl -H "Authorization: Bearer $TOKEN" $BASE_URL/api/pets

echo "\nInserting pet:"

curl -v \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Nero"}' \
  $BASE_URL/api/pets

# Esta deberia dar un 403 porque no tiene el rol adecuado
