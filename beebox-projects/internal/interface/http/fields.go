package httpapi

import (
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
)

func (s *Server) getFields(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	fields, err := s.ListFields.Execute(r.Context(), ownerID, projectID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if fields == nil {
		fields = []domain.Field{}
	}
	out := make([]fieldDTO, 0, len(fields))
	for _, field := range fields {
		out = append(out, toFieldDTO(field))
	}
	writeJSON(w, http.StatusOK, map[string]any{"fields": out})
}

func (s *Server) putFields(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Fields []struct {
			Name             string `json:"name"`
			Type             string `json:"type"`
			Required         bool   `json:"required"`
			UniquePerProject bool   `json:"unique_per_project"`
		} `json:"fields"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	inputs := make([]domain.FieldInput, 0, len(body.Fields))
	for _, field := range body.Fields {
		inputs = append(inputs, domain.FieldInput{
			Name:             field.Name,
			Type:             field.Type,
			Required:         field.Required,
			UniquePerProject: field.UniquePerProject,
		})
	}
	fields, err := s.PutFields.Execute(r.Context(), ownerID, projectID, inputs)
	if err != nil {
		writeErr(w, err)
		return
	}
	if fields == nil {
		fields = []domain.Field{}
	}
	out := make([]fieldDTO, 0, len(fields))
	for _, field := range fields {
		out = append(out, toFieldDTO(field))
	}
	writeJSON(w, http.StatusOK, map[string]any{"fields": out})
}
