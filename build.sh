#!/bin/bash -e

function build() {
	rm -rf build
	mkdir build

	GOOS=linux GOARCH=$1 go build -o build/threshold

	sha256sum build/threshold

	cd build
	tar -czvf threshold-$1.tar.gz threshold
	cd ../

	sha256sum build/threshold-$1.tar.gz

	FILE_PATH="threshold-$1.tar.gz"
	FILE_NAME="build/threshold-$1.tar.gz"

	BUCKET_NAME="server-garden-artifacts"
	AUTH_JSON="$(curl -sS -u "$BACKBLAZE_CRED" https://api.backblazeb2.com/b2api/v2/b2_authorize_account)"

	API_URL="$(echo "$AUTH_JSON" | grep -E -o '"apiUrl": "([^"]+)"' | sed -E 's|"apiUrl": "([^"]+)"|\1|')"
	ACCOUNT_ID="$(echo "$AUTH_JSON" | grep -E -o '"accountId": "([^"]+)"' | sed -E 's|"accountId": "([^"]+)"|\1|')"
	AUTH_TOKEN="$(echo "$AUTH_JSON" | grep -E -o '"authorizationToken": "([^"]+)"' | sed -E 's|"authorizationToken": "([^"]+)"|\1|')"

	LIST_BUCKETS_JSON="$(curl -sS -H "Authorization: $AUTH_TOKEN" "$API_URL/b2api/v2/b2_list_buckets?accountId=$ACCOUNT_ID&bucketName=$BUCKET_NAME" )"
	BUCKET_ID="$(echo "$LIST_BUCKETS_JSON" | grep -E -o '"bucketId": "([^"]+)"' | sed -E 's|"bucketId": "([^"]+)"|\1|')"

	UPLOAD_URL_JSON="$(curl -sS -H "Authorization: $AUTH_TOKEN" "$API_URL/b2api/v2/b2_get_upload_url?bucketId=$BUCKET_ID" )"

	UPLOAD_URL="$(echo "$UPLOAD_URL_JSON" | grep -E -o '"uploadUrl": "([^"]+)"' | sed -E 's|"uploadUrl": "([^"]+)"|\1|')"
	AUTH_TOKEN="$(echo "$UPLOAD_URL_JSON" | grep -E -o '"authorizationToken": "([^"]+)"' | sed -E 's|"authorizationToken": "([^"]+)"|\1|')"

	CONTENT_SHA1="$(cat "$FILE_NAME" | sha1sum | awk '{ print $1 }')"

	curl -sS -X POST \
		-H "Authorization: $AUTH_TOKEN" \
		-H "X-Bz-File-Name: $FILE_PATH" \
		-H "X-Bz-Content-Sha1: $CONTENT_SHA1" \
		-H "Content-Type: text/plain" \
		"$UPLOAD_URL" --data-binary @"$FILE_NAME"


}

build arm
build amd64
build arm64