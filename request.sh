#!/bin/bash

BASE_URL="http://localhost:8080/sample-jwt-web"
HEADERS_FILE="response-headers.txt"

if [ -f $HEADERS_FILE ] ; then
  rm $HEADERS_FILE
fi

curl --dump-header $HEADERS_FILE \
  -H 'Content-Type: application/json' \
  -d '{ "username": "user", "password": "user"}' \
	$BASE_URL/login

TOKEN=$(grep Authorization $HEADERS_FILE | cut -d' ' -f3)

echo "Readed JWT Token: $TOKEN"

curl -H "Authorization: Bearer $TOKEN" $BASE_URL/api/pets
