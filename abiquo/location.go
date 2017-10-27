package abiquo_api

type LocationCollection struct {
	AbstractCollection
	Collection []Location
}

type Location struct {
	DTO
	Name     string `json:"name,omitempty"`
	Location string `json:"location,omitempty"`
}
