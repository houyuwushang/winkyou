//go:build !linux || !fieldc1c

package main

func dispatchDeploymentWrapper() (bool, error) { return false, nil }
