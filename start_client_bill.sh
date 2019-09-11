#!/usr/bin/env bash
mvn exec:java -Dexec.mainClass="client.AuthClient" -Dexec.args="bill password456"