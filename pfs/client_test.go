package pfs

import (
	"encoding/json"
	"testing"

	"encoding/base64"
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"
)

const responseText = `{"id":"1b77a7cd289dfd1ca89240574148d0ac67c1f8cdc8e26a452e26e7c0331e88b4","content_snapshot":"eyJpZGVudGl0eSI6Ijc2NWFkMGFkN2EyNGFhODYzOWRlNzFkMTVmZmFjZGZlNDM4MzczNDQ5YzJjY2YxNzIwNGJkYWE5NmE5ZmE0MTIiLCJpZGVudGl0eV90eXBlIjoib3RjIiwicHVibGljX2tleSI6Ik1Db3dCUVlESzJWd0F5RUEvdzNOR0dTY2VGMU1Yc1hERDdjdmhYNUVpcCtDQTFxODhaaEFsb1VVVXcwPSIsInNjb3BlIjoiYXBwbGljYXRpb24iLCJpbmZvIjpudWxsfQ==","meta":{"created_at":"2017-06-20T14:06:31+0000","card_version":"4.0","signs":{"1b77a7cd289dfd1ca89240574148d0ac67c1f8cdc8e26a452e26e7c0331e88b4":"MFEwDQYJYIZIAWUDBAICBQAEQCYSyqZL2KLKDoU1UFY6tuox1rPPBMH4CYIxv4lV31xsKUMhSLBokGDMYTl5XmNd+SyvovIGrVf7wZczTzPHuwE=","4f3ec3cbe11e14bcfbb6265abf03c4a21d6098d4aedbc06fb668c2f62cc93ef8":"MFEwDQYJYIZIAWUDBAICBQAEQHu9zlYE592GAzhxNWAdjoOE9rr/G4Kj9V/FNrX9oa3x4G/57TQ8ILZzlze7rFlDT5j9azYr65VN2FV/MhbwDQA=","765ad0ad7a24aa8639de71d15ffacdfe438373449c2ccf17204bdaa96a9fa412":"MFEwDQYJYIZIAWUDBAICBQAEQKjHqWpbJ7lmmtgKpUrVH+Chh2aqTolpvDei/NRy3Dm7qYlfrL5MhLnw59EZOCUByTnDmPmj03rwGJIEhI4m/gE=","e680bef87ba75d331b0a02bfa6a20f02eb5c5ba9bc96fc61ca595404b10026f4":"MFEwDQYJYIZIAWUDBAICBQAEQBQU2IyJq7H3kWidSW1bjiU1v9ael9DfAbNhL4e4X+/0+HHc6Kagin9sY+vuYraFnSV4QCI0Pxj4maaeOp6pUQI="},"relations":{}}}`
const pubText = `MCowBQYDK2VwAyEAmXezqV72m5aC0+S7VfZ2s+6lt2NH9Qx0M+7SjILeV0w=`

func BenchmarkClient_ResponseToCard(b *testing.B) {

	validator := virgil.NewCardsValidator()

	pubBytes, err := base64.StdEncoding.DecodeString(pubText)
	if err != nil {
		panic(err)
	}
	pub, err := virgil.Crypto().ImportPublicKey([]byte(pubBytes))
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var resp *virgil.CardResponse
		err := json.Unmarshal([]byte(responseText), &resp)
		if err != nil {
			panic(err)
		}

		card, err := resp.ToCard()
		if err != nil {
			panic(err)
		}
		err = validator.ValidateExtra(card, map[string]virgilcrypto.PublicKey{
			"765ad0ad7a24aa8639de71d15ffacdfe438373449c2ccf17204bdaa96a9fa412": pub,
		})

		if err != nil {
			panic(err)
		}
	}
}
