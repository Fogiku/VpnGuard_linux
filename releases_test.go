package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestPublishedReleaseNotes(t *testing.T) {
	if len(releases) == 0 || releases[0].Version != Version {
		t.Fatal("current release must head the Updates page")
	}
	for i, r := range releases {
		if r.Date == "" || len(r.Changes) == 0 || (i > 0 && !newerRelease(releases[i-1].Version, r.Version)) {
			t.Fatalf("missing date, notes or version ordering for %s", r.Version)
		}
	}
	for _, version := range []string{"1.9.24", "1.9.25", "1.9.26"} {
		found := false
		for _, r := range releases {
			if r.Version == version {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing historical release %s", version)
		}
	}
	if !reflect.DeepEqual(recentReleases(changeLog), recentReleases(strings.ReplaceAll(changeLog, "\n", "\r\n"))) {
		t.Fatal("CRLF changed release cards")
	}
}
