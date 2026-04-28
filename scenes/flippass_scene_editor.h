#pragma once

#include <gui/scene_manager.h>
#include <stddef.h>

struct App;
struct KDBXCustomField;
struct FlipPassEditorCustomFieldDraft;

void flippass_editor_clear_custom_field_drafts(struct App* app);
size_t flippass_editor_custom_field_count(const struct App* app);
void flippass_editor_prepare_new_custom_field(struct App* app);
void flippass_editor_prepare_edit_custom_field(
    struct App* app,
    struct KDBXCustomField* field,
    struct FlipPassEditorCustomFieldDraft* draft);
void flippass_scene_editor_on_enter(void* context);
bool flippass_scene_editor_on_event(void* context, SceneManagerEvent event);
void flippass_scene_editor_on_exit(void* context);

void flippass_scene_editor_text_input_on_enter(void* context);
bool flippass_scene_editor_text_input_on_event(void* context, SceneManagerEvent event);
void flippass_scene_editor_text_input_on_exit(void* context);
