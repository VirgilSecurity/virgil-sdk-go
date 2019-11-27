package cryptocgo

type deleter interface {
	Delete()
}

func delete(lst ...deleter) {
	for _, i := range lst {
		if i != nil {
			i.Delete()
		}
	}
}
