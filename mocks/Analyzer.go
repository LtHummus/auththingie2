// Code generated by mockery v2.39.1. DO NOT EDIT.

package mocks

import (
	rules "github.com/lthummus/auththingie2/rules"
	mock "github.com/stretchr/testify/mock"
)

// Analyzer is an autogenerated mock type for the Analyzer type
type Analyzer struct {
	mock.Mock
}

// AddRule provides a mock function with given fields: r
func (_m *Analyzer) AddRule(r rules.Rule) {
	_m.Called(r)
}

// Errors provides a mock function with given fields:
func (_m *Analyzer) Errors() []string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Errors")
	}

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// KnownRoles provides a mock function with given fields:
func (_m *Analyzer) KnownRoles() []string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for KnownRoles")
	}

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// MatchesRule provides a mock function with given fields: ri
func (_m *Analyzer) MatchesRule(ri *rules.RequestInfo) *rules.Rule {
	ret := _m.Called(ri)

	if len(ret) == 0 {
		panic("no return value specified for MatchesRule")
	}

	var r0 *rules.Rule
	if rf, ok := ret.Get(0).(func(*rules.RequestInfo) *rules.Rule); ok {
		r0 = rf(ri)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*rules.Rule)
		}
	}

	return r0
}

// Rules provides a mock function with given fields:
func (_m *Analyzer) Rules() []rules.Rule {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Rules")
	}

	var r0 []rules.Rule
	if rf, ok := ret.Get(0).(func() []rules.Rule); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]rules.Rule)
		}
	}

	return r0
}

// WriteConfig provides a mock function with given fields:
func (_m *Analyzer) WriteConfig() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for WriteConfig")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewAnalyzer creates a new instance of Analyzer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAnalyzer(t interface {
	mock.TestingT
	Cleanup(func())
}) *Analyzer {
	mock := &Analyzer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
