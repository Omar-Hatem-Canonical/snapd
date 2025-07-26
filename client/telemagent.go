// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)


func (c *Client) DeviceSession() (deviceSession []string, err error) {
	_, err = c.doSync("GET", "/v2/devicesession", nil, nil, nil, &deviceSession)

	if len(deviceSession) != 1 {
		err = errors.New("number of macaroons found not equal to 1")
	}

	return
}

func (c *Client) Associate(email string, password string, otp string) error {
	url := "http://localhost:1234"

	var payload struct {
		Email     string  `json:"email"`
		Password  string  `json:"password"`
		OTP       string  `json:"otp"`
		Macaroon  string  `json:"macaroon"`
	}

	payload.Email = email
	payload.Password = password
	payload.OTP = otp

	macaroon, err := c.DeviceSession()
	if err != nil {
		return err
	}

	payload.Macaroon = macaroon[0]

	jsonBytes, err := json.Marshal(payload)
		if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
    req.Header.Set("Content-Type", "application/json")
	if err != nil {
        return err
    }

    client := &http.Client{
		Timeout: 5 * time.Second,
	}
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

	
    body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
    }
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not associate device: %s", string(body))
	}

	return nil
}