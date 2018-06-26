package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestExtractFilterGroups(t *testing.T) {
	assert.Equal(t, []string(nil), extractFilterGroups(""))
	assert.Equal(t, []string(nil), extractFilterGroups(","))
	assert.Equal(t, []string{"test", "me", "please" , "foo bar"}, extractFilterGroups(",test, me,please ,,    ,foo bar"))
	assert.Equal(t, []string{"*"}, extractFilterGroups("foo,*,bar"))
}
