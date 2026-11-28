package main

import (
	"encoding/hex"
	"errors"
	"time"
)

type discordSample struct {
	UTC                time.Time `json:"utc"`
	ControlUTC         time.Time `json:"controlUTC"`
	Outcome            string    `json:"outcome"`
	ControlHTTP        int       `json:"controlHTTP"`
	ControlTLS         bool      `json:"controlTLS"`
	ControlPolicy      string    `json:"controlPolicy"`
	ControlCorrelation string    `json:"controlCorrelation"`
	Correlation        string    `json:"correlation"`
	Exit               string    `json:"exit"`
	Policy             string    `json:"policy"`
	Profile            string    `json:"profile"`
}

func discordEvidence(samples []discordSample, now time.Time) string {
	if len(samples) == 1 && samples[0].Outcome == "hello" {
		return "Discord Gateway ответил Hello."
	}
	if len(samples) != 2 {
		return "Нужны два завершённых клиентских замера."
	}
	var prev time.Time
	for _, s := range samples {
		if s.Outcome == "hello" {
			return "Сбой Discord Gateway не повторился."
		}
		if s.Outcome != "timeout" && s.Outcome != "connection_reset" && s.Outcome != "closed_before_hello" {
			return "Не установлен характер сбоя соединения Discord."
		}
		if !s.UTC.After(prev) || now.Sub(s.UTC) > 5*time.Minute || s.UTC.After(now) || s.ControlUTC.Before(s.UTC) || s.ControlUTC.After(now) {
			return "Замеры устарели или нарушена последовательность."
		}
		prev = s.ControlUTC
		if !s.ControlTLS || s.ControlHTTP < 200 || s.ControlHTTP >= 300 {
			return "Независимая HTTPS-проверка не прошла."
		}
		if s.Correlation != "pin_and_observed_policy" || s.Exit != "zapret" || s.ControlCorrelation != "pin_and_observed_policy" || s.Policy != s.ControlPolicy || s.Policy != samples[0].Policy || s.Profile != samples[0].Profile {
			return "Не подтверждены закрепление TCP-потока за zapret и стабильность ревизий."
		}
		for _, hash := range []string{s.Policy, s.Profile} {
			if len(hash) != 64 {
				return "Нет ревизии профиля или маршрутизации."
			}
			if _, err := hex.DecodeString(hash); err != nil {
				return "Некорректная ревизия."
			}
		}
	}
	return ""
}

func discordFlowDraft(samples []discordSample) (zapretDraft, error) {
	wait := func(reason string) (zapretDraft, error) {
		return zapretDraft{zapretProposal: zapretProposal{Status: "need_data", Reason: reason}}, nil
	}
	if reason := discordEvidence(samples, time.Now()); reason != "" {
		return wait(reason)
	}
	if !cfgBool("zapret.flowDraft", false) {
		return wait("Сбой зарегистрирован. Генерация по клиентской пробе отключена.")
	}
	if !cfgBool("zapret.enabled", true) || !active(zUnit) {
		return wait("Служба zapret2 выключена.")
	}
	raw, err := S.ReadFile(zArgs)
	if err != nil {
		return zapretDraft{}, err
	}
	for _, base := range builtinZapretStrategies() {
		if draftHash(base.Args) != samples[0].Profile || raw != base.Args+"\n" {
			continue
		}
		if aiModel() == "" {
			return zapretDraft{}, errors.New("выберите локальную модель Ollama")
		}
		if !allow("zapret.flowDraft", 1, time.Hour) {
			return wait("Достигнут лимит генерации по потоку: одна попытка за час работы агента.")
		}
		return generateZapretDraft(base.Name, "discord", "failed", aiModel(), "http://127.0.0.1:11434/api/chat", samples...)
	}
	return wait("Текущий файл параметров не совпадает с наблюдаемой поддерживаемой ревизией.")
}
