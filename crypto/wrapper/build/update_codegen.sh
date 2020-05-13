#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TEMPDIR=`mktemp -d`

if [[ -z "$BRANCH" ]]; then
  BRANCH=master;
fi

git clone -b $BRANCH https://github.com/VirgilSecurity/virgil-crypto-c.git $TEMPDIR

RETRES=$?
echo $RETRES
if [ "$RETRES" == "0" ]; then
  rm  -rf $SCRIPT_FOLDER/../{foundation,phe};
  cp -R $TEMPDIR/wrappers/go/{foundation,phe} $SCRIPT_FOLDER/../;
  for i in $(grep -R "virgil/foundation" $SCRIPT_FOLDER/../{foundation,phe} | cut -d ":" -f 1)
  do
  	echo  $i
    sed -i '' 's/virgil\/foundation/github.com\/VirgilSecurity\/virgil-sdk-go\/v6\/crypto\/wrapper\/foundation/g' $i
  done;
fi
rm -rf $TEMPDIR