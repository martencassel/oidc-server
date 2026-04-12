#!/bin/bash

curl -v -X GET \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "response_type=code" \
  -d "client_id=client123" \
  -d "redirect_uri=https%3A%2F%2Fexample.com%2Fcallback" \
  http://localhost:8080/oauth2/authorize
