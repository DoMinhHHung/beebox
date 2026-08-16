-- +goose Up
-- Version 1 intentionally creates no product schema, table, or data. It
-- anchors BeeBox's immutable forward-migration history before product data
-- ownership and tenancy contracts are selected.
SELECT 1;
