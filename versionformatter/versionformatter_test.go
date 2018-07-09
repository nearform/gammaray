package versionformatter

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSemverVersion(t *testing.T) {
	res, _ := Format("1.0.0-rc1")
	fmt.Println("TestSemverVersion result:", res)
	if diff := cmp.Diff(res, "1.0.0-rc1"); diff != "" {
		t.Errorf("TestSemverVersion: after Format : (-got +want)\n%s", diff)
	}
}

func TestNotSemverVersion(t *testing.T) {
	res, _ := Format("1.0.rc.1")
	fmt.Println("TestNotSemverVersion result:", res)
	if diff := cmp.Diff(res, "1.0.0-rc.1"); diff != "" {
		t.Errorf("TestNotSemverVersion: after Format : (-got +want)\n%s", diff)
	}
}

func TestNotSemverVersionAgain(t *testing.T) {
	res, _ := Format("0.8.beta-1")
	fmt.Println("TestNotSemverVersionAgain result:", res)
	if diff := cmp.Diff(res, "0.8.0-beta-1"); diff != "" {
		t.Errorf("TestNotSemverVersionAgain: after Format : (-got +want)\n%s", diff)
	}
}

func TestNotSemverSimpleExpression(t *testing.T) {
	res, _ := Format("<0.8")
	fmt.Println("TestNotSemverSimpleExpression result:", res)
	if diff := cmp.Diff(res, "<0.8.0"); diff != "" {
		t.Errorf("TestNotSemverSimpleExpression: after Format : (-got +want)\n%s", diff)
	}
}

func TestSemverAndExpression(t *testing.T) {
	res, _ := Format(">=1.1.0 <=1.1.1")
	fmt.Println("TestNotSemverSimpleExpression result:", res)
	if diff := cmp.Diff(res, ">=1.1.0, <=1.1.1"); diff != "" {
		t.Errorf("TestNotSemverSimpleExpression: after Format : (-got +want)\n%s", diff)
	}
}

func TestSemverOrExpression(t *testing.T) {
	res, _ := Format(">=1.1.0 || <=1.1.1")
	fmt.Println("TestSemverOrExpression result:", res)
	if diff := cmp.Diff(res, ">=1.1.0 || <=1.1.1"); diff != "" {
		t.Errorf("TestSemverOrExpression: after Format : (-got +want)\n%s", diff)
	}
}

func TestComplexExpression(t *testing.T) {
	res, _ := Format(" >=0.08beta-1 || !1.rc.1 <=1.rc+build.543 || >2 ")
	fmt.Println("TestComplexExpression result:", res)
	if diff := cmp.Diff(res, ">=0.8.0-beta-1 || !1.0.0-rc.1 <=1.0.0-rc+build.543 || >2.0.0"); diff != "" {
		t.Errorf("TestComplexExpression: after Format : (-got +want)\n%s", diff)
	}
}

func TestSimplePipeExpression(t *testing.T) {
	res, _ := Format("2.0.0 2.0.0-x | 2.1.0-x 2.1.1 2.1.2")
	fmt.Println("TestSimplePipeExpression result:", res)
	if diff := cmp.Diff(res, "2.0.0, 2.0.0-x, 2.1.0-x, 2.1.1, 2.1.2"); diff != "" {
		t.Errorf("TestComplexExpression: after Format : (-got +want)\n%s", diff)
	}
}
