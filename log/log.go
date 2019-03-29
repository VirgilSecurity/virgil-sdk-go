/*
 * Copyright (C) 2015-2019 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   (1) Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   (2) Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 *   (3) Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

package log

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/x-cray/logrus-prefixed-formatter"
)

type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelWarn
	LogLevelError
)

type Logger interface {
	Log(severity LogLevel, message string)
}

var Default *internalLogger

type internalLogger struct {
	level LogLevel
	log   Logger
}

func (d *internalLogger) Debugf(format string, args ...string) {
	if d.log != nil && d.level == LogLevelDebug {
		d.log.Log(LogLevelDebug, fmt.Sprintf(format, args))
	}
}

func (d *internalLogger) Warnf(format string, args ...string) {
	if d.log != nil && d.level <= LogLevelWarn {
		d.log.Log(LogLevelWarn, fmt.Sprintf(format, args))
	}
}

func (d *internalLogger) Errorf(format string, args ...string) {
	if d.log != nil && d.level <= LogLevelError {
		d.log.Log(LogLevelError, fmt.Sprintf(format, args))
	}
}

type logrusWrapper struct {
	*logrus.Logger
}

func (w *logrusWrapper) Log(severity LogLevel, message string) {
	switch severity {
	case LogLevelDebug:
		w.Logger.Debug(message)
		break
	case LogLevelWarn:
		w.Logger.Warn(message)
		break
	case LogLevelError:
		w.Logger.Error(message)
		break
	default:
		break
	}
}

func SetLogger(logger Logger) {
	Default.log = logger
}

func SetLogLevel(level LogLevel) {
	if level >= LogLevelDebug && level <= LogLevelError {
		Default.level = level
	}
}

func init() {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.SetFormatter(&prefixed.TextFormatter{
		DisableColors:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
		ForceFormatting: true,
	})

	Default = &internalLogger{
		log:   &logrusWrapper{Logger: logger},
		level: LogLevelError,
	}
}
