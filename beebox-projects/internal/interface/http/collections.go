package httpapi

import (
	"net/http"

	"github.com/DoMinhHHung/beebox/beebox-projects/internal/domain"
	"github.com/google/uuid"
)

func (s *Server) getCollections(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	items, err := s.ListCollections.Execute(r.Context(), ownerID, projectID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if items == nil {
		items = []domain.Collection{}
	}
	out := make([]collectionDTO, 0, len(items))
	for _, item := range items {
		out = append(out, toCollectionDTO(item))
	}
	writeJSON(w, http.StatusOK, map[string]any{"collections": out})
}

func (s *Server) postCollection(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	item, err := s.CreateCollection.Execute(r.Context(), ownerID, projectID, body.Name, body.Slug)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCollectionDTO(item))
}

func (s *Server) getDocuments(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, collectionID, err := ownerCollection(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	items, err := s.ListDocuments.Execute(r.Context(), ownerID, projectID, collectionID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if items == nil {
		items = []domain.Document{}
	}
	out := make([]documentDTO, 0, len(items))
	for _, item := range items {
		out = append(out, toDocumentDTO(item))
	}
	writeJSON(w, http.StatusOK, map[string]any{"documents": out})
}

func (s *Server) postDocument(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, collectionID, err := ownerCollection(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	item, err := s.CreateDocument.Execute(r.Context(), ownerID, projectID, collectionID, body.Data)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toDocumentDTO(item))
}

func (s *Server) getDocument(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, collectionID, documentID, err := ownerDocument(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	item, err := s.GetDocument.Execute(r.Context(), ownerID, projectID, collectionID, documentID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentDTO(item))
}

func (s *Server) patchDocument(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, collectionID, documentID, err := ownerDocument(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, domain.ErrInvalidInput)
		return
	}
	item, err := s.UpdateDocument.Execute(r.Context(), ownerID, projectID, collectionID, documentID, body.Data)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentDTO(item))
}

func (s *Server) deleteDocument(w http.ResponseWriter, r *http.Request) {
	ownerID, projectID, collectionID, documentID, err := ownerDocument(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := s.DeleteDocument.Execute(r.Context(), ownerID, projectID, collectionID, documentID); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func ownerCollection(r *http.Request) (uuid.UUID, uuid.UUID, uuid.UUID, error) {
	ownerID, projectID, err := ownerProject(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	collectionID, err := pathUUID(r, "collectionId")
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	return ownerID, projectID, collectionID, nil
}

func ownerDocument(r *http.Request) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, error) {
	ownerID, projectID, collectionID, err := ownerCollection(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	documentID, err := pathUUID(r, "documentId")
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	return ownerID, projectID, collectionID, documentID, nil
}

type collectionDTO struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	CreatedAt string `json:"created_at"`
}

type documentDTO struct {
	ID           string         `json:"id"`
	ProjectID    string         `json:"project_id"`
	CollectionID string         `json:"collection_id"`
	Data         map[string]any `json:"data"`
	CreatedAt    string         `json:"created_at"`
	UpdatedAt    string         `json:"updated_at"`
}

func toCollectionDTO(item domain.Collection) collectionDTO {
	return collectionDTO{
		ID: item.ID.String(), ProjectID: item.ProjectID.String(), Name: item.Name, Slug: item.Slug,
		CreatedAt: item.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

func toDocumentDTO(item domain.Document) documentDTO {
	data := item.Data
	if data == nil {
		data = map[string]any{}
	}
	return documentDTO{
		ID: item.ID.String(), ProjectID: item.ProjectID.String(), CollectionID: item.CollectionID.String(), Data: data,
		CreatedAt: item.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: item.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}
