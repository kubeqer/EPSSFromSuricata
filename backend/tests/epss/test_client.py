import pytest
from unittest.mock import patch, MagicMock
import httpx
import csv
import os
from datetime import datetime
from io import StringIO

from src.epss.client import EPSSClient
from src.epss.exceptions import EPSSAPIException, EPSSOfflineFileNotFound, EPSSOfflineParsingError

@pytest.mark.asyncio
async def test_get_scores_api_success():
    with patch('httpx.AsyncClient') as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"cve": "CVE-2023-1234", "epss": 0.5, "percentile": 99.5},
                {"cve": "CVE-2023-5678", "epss": 0.2, "percentile": 85.0}
            ]
        }
        mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

        client = EPSSClient()
        result = await client.get_scores(["CVE-2023-1234", "CVE-2023-5678"])

        assert result["CVE-2023-1234"] == (0.5, 99.5)
        assert result["CVE-2023-5678"] == (0.2, 85.0)

@pytest.mark.asyncio
async def test_get_scores_api_failure():
    with patch('httpx.AsyncClient') as mock_client:
        mock_client.return_value.__aenter__.return_value.get.side_effect = httpx.RequestError("Connection error")

        client = EPSSClient()
        with pytest.raises(EPSSAPIException):
            await client.get_scores(["CVE-2023-1234"])



def test_get_scores_offline_file_not_found():
    client = EPSSClient()
    client.offline_path = "/nonexistent/file.csv"
    client.use_offline = True

    with pytest.raises(EPSSOfflineFileNotFound):
        client._get_scores_offline(["CVE-2023-1234"])

