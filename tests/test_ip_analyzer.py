import importlib
import ip_analyzer
import pytest


def test_validate_ip_valid_v4():
    assert ip_analyzer.validate_ip('8.8.8.8') is True


def test_validate_ip_invalid():
    assert ip_analyzer.validate_ip('999.999.999.999') is False


def test_analizar_ip_handles_missing_requests(monkeypatch, capsys):
    # Simular que requests no está disponible
    monkeypatch.setattr(ip_analyzer, 'requests', None)

    # Esto no debe lanzar excepción; debe imprimir un mensaje de error para la parte de requests
    ip_analyzer.analizar_ip('127.0.0.1')
    captured = capsys.readouterr()
    assert 'Error' in captured.out or 'No disponible' in captured.out


if __name__ == '__main__':
    pytest.main([__file__])
