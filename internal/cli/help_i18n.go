package cli

import "sentinelhttp/internal/core/localization"

func helpText(lang localization.Locale, command string) string {
	if lang == localization.English {
		switch command {
		case "diff":
			return diffHelp
		case "serve":
			return serveHelp
		default:
			return scanHelp
		}
	}
	switch lang {
	case localization.Spanish:
		switch command {
		case "diff":
			return "Uso: sentinelhttp diff OLD.json NEW.json [--format terminal|json] [--output FILE] [--lang es]\nLos informes se procesan como datos no confiables. No se realizan solicitudes de red.\n"
		case "serve":
			return "Uso: sentinelhttp serve REPORT.json [--compare OLD.json] [--no-open] [--lang es]\nSirve un informe validado en un puerto aleatorio de 127.0.0.1. Ctrl+C detiene el servidor.\n"
		default:
			return "Uso: sentinelhttp scan TARGET [opciones] [--lang es]\nEvaluá solo sistemas propios o para los que tengas autorización.\nOpciones: --format terminal|json|markdown|html, --output FILE,\n  --allow-private, --same-host, --trace-redirects, --probe-cors,\n  --max-redirects 1..20, --max-requests 1..24, --timeout DURATION,\n  --connect-timeout DURATION, --max-response-bytes N, --ca-file PEM.\nHTTPS en Windows/macOS/iOS requiere --ca-file para verificar sin conexión.\n"
		}
	case localization.Russian:
		switch command {
		case "diff":
			return "Использование: sentinelhttp diff OLD.json NEW.json [--format terminal|json] [--output FILE] [--lang ru]\nОтчёты обрабатываются как недоверенные данные. Сетевые запросы не выполняются.\n"
		case "serve":
			return "Использование: sentinelhttp serve REPORT.json [--compare OLD.json] [--no-open] [--lang ru]\nПроверенный отчёт обслуживается на случайном порту 127.0.0.1. Ctrl+C останавливает сервер.\n"
		default:
			return "Использование: sentinelhttp scan TARGET [параметры] [--lang ru]\nПроверяйте только собственные системы или системы с разрешением.\nПараметры: --format terminal|json|markdown|html, --output FILE,\n  --allow-private, --same-host, --trace-redirects, --probe-cors,\n  --max-redirects 1..20, --max-requests 1..24, --timeout DURATION,\n  --connect-timeout DURATION, --max-response-bytes N, --ca-file PEM.\nДля HTTPS в Windows/macOS/iOS нужен --ca-file для автономной проверки.\n"
		}
	case localization.Chinese:
		switch command {
		case "diff":
			return "用法：sentinelhttp diff OLD.json NEW.json [--format terminal|json] [--output FILE] [--lang zh-CN]\n报告按不可信输入处理。不会发起网络请求。\n"
		case "serve":
			return "用法：sentinelhttp serve REPORT.json [--compare OLD.json] [--no-open] [--lang zh-CN]\n在 127.0.0.1 的随机端口提供已验证报告。按 Ctrl+C 停止。\n"
		default:
			return "用法：sentinelhttp scan TARGET [选项] [--lang zh-CN]\n仅评估您拥有或获准测试的系统。\n选项：--format terminal|json|markdown|html, --output FILE,\n  --allow-private, --same-host, --trace-redirects, --probe-cors,\n  --max-redirects 1..20, --max-requests 1..24, --timeout DURATION,\n  --connect-timeout DURATION, --max-response-bytes N, --ca-file PEM。\nWindows/macOS/iOS 上的 HTTPS 需要 --ca-file 才能离线验证。\n"
		}
	default:
		return scanHelp
	}
}
