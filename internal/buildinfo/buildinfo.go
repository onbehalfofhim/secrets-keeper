package buildinfo

var (
	// Версия приложения.
	// При сборке может быть переопределена через ldflags.
	Version = "dev"

	// Дата сборки приложения.
	// При сборке может быть переопределена через ldflags.
	BuildDate = "unknown"
)

// Info содержит информацию о версии и дате сборки бинарного файла.
type Info struct {
	Version   string
	BuildDate string
}

// Get возвращает информацию о версии и дате сборки приложения.
func Get() Info {
	return Info{
		Version:   Version,
		BuildDate: BuildDate,
	}
}
