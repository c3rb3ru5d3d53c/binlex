#include "assembler.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>

namespace {

struct DiagBuffer {
  std::string message;
};

void append_message(const llvm::SMDiagnostic &diagnostic, void *context) {
  auto *buffer = static_cast<DiagBuffer *>(context);
  if (buffer == nullptr) {
    return;
  }
  std::string rendered;
  llvm::raw_string_ostream stream(rendered);
  diagnostic.print("binlex", stream, false);
  stream.flush();
  if (!buffer->message.empty()) {
    buffer->message.push_back('\n');
  }
  buffer->message += rendered;
}

char *copy_error(const std::string &message) {
  auto *result = static_cast<char *>(std::malloc(message.size() + 1));
  if (result == nullptr) {
    return nullptr;
  }
  std::memcpy(result, message.c_str(), message.size() + 1);
  return result;
}

bool set_error(const std::string &message, char **error) {
  if (error != nullptr) {
    *error = copy_error(message);
  }
  return false;
}

bool initialize_target(llvm::Triple::ArchType arch, char **error) {
  static std::once_flag x86_once;
  static std::once_flag aarch64_once;

  switch (arch) {
  case llvm::Triple::x86:
  case llvm::Triple::x86_64:
    std::call_once(x86_once, []() {
      LLVMInitializeX86TargetInfo();
      LLVMInitializeX86Target();
      LLVMInitializeX86TargetMC();
      LLVMInitializeX86AsmParser();
    });
    return true;
  case llvm::Triple::aarch64:
  case llvm::Triple::aarch64_be:
    std::call_once(aarch64_once, []() {
      LLVMInitializeAArch64TargetInfo();
      LLVMInitializeAArch64Target();
      LLVMInitializeAArch64TargetMC();
      LLVMInitializeAArch64AsmParser();
    });
    return true;
  default:
    return set_error("unsupported llvm target architecture", error);
  }
}

} // namespace

extern "C" bool binlex_llvm_assemble_to_object(const char *triple_cstr,
                                                const char *cpu_cstr,
                                                const char *assembly_cstr,
                                                std::uint8_t **bytes,
                                                std::size_t *length,
                                                char **error) {
  if (bytes == nullptr || length == nullptr || triple_cstr == nullptr ||
      assembly_cstr == nullptr) {
    return set_error("invalid assembler arguments", error);
  }

  *bytes = nullptr;
  *length = 0;
  if (error != nullptr) {
    *error = nullptr;
  }

  const std::string triple_string(triple_cstr);
  llvm::Triple triple(triple_string);
  if (!initialize_target(triple.getArch(), error)) {
    return false;
  }
  std::string target_error;
  const llvm::Target *target =
      llvm::TargetRegistry::lookupTarget(triple, target_error);
  if (target == nullptr) {
    return set_error(target_error.empty() ? "failed to look up llvm target"
                                          : target_error,
                     error);
  }

  llvm::MCTargetOptions options;
  const char *cpu = cpu_cstr != nullptr ? cpu_cstr : "generic";

  auto register_info =
      std::unique_ptr<llvm::MCRegisterInfo>(target->createMCRegInfo(triple));
  if (!register_info) {
    return set_error("failed to create llvm register info", error);
  }

  auto asm_info = std::unique_ptr<llvm::MCAsmInfo>(
      target->createMCAsmInfo(*register_info, triple, options));
  if (!asm_info) {
    return set_error("failed to create llvm asm info", error);
  }

  auto instr_info =
      std::unique_ptr<llvm::MCInstrInfo>(target->createMCInstrInfo());
  if (!instr_info) {
    return set_error("failed to create llvm instruction info", error);
  }

  auto subtarget_info = std::unique_ptr<llvm::MCSubtargetInfo>(
      target->createMCSubtargetInfo(triple, cpu, ""));
  if (!subtarget_info) {
    return set_error("failed to create llvm subtarget info", error);
  }

  llvm::SourceMgr source_manager;
  DiagBuffer diagnostics;
  source_manager.setDiagHandler(append_message, &diagnostics);
  source_manager.AddNewSourceBuffer(
      llvm::MemoryBuffer::getMemBuffer(llvm::StringRef(assembly_cstr), "<binlex>", false),
      llvm::SMLoc());

  llvm::MCObjectFileInfo object_file_info;
  llvm::MCContext context(triple, asm_info.get(), register_info.get(),
                          subtarget_info.get(), &source_manager, &options);
  object_file_info.initMCObjectFileInfo(context, false);
  context.setObjectFileInfo(&object_file_info);

  auto emitter =
      std::unique_ptr<llvm::MCCodeEmitter>(target->createMCCodeEmitter(*instr_info, context));
  if (!emitter) {
    return set_error("failed to create llvm code emitter", error);
  }

  auto asm_backend = std::unique_ptr<llvm::MCAsmBackend>(
      target->createMCAsmBackend(*subtarget_info, *register_info, options));
  if (!asm_backend) {
    return set_error("failed to create llvm asm backend", error);
  }

  llvm::SmallVector<char, 0> object_storage;
  llvm::raw_svector_ostream object_stream(object_storage);
  auto writer = asm_backend->createObjectWriter(object_stream);
  if (!writer) {
    return set_error("failed to create llvm object writer", error);
  }

  auto streamer = std::unique_ptr<llvm::MCStreamer>(
      target->createMCObjectStreamer(triple, context, std::move(asm_backend),
                                     std::move(writer), std::move(emitter),
                                     *subtarget_info));
  if (!streamer) {
    return set_error("failed to create llvm object streamer", error);
  }

  auto parser = std::unique_ptr<llvm::MCAsmParser>(
      llvm::createMCAsmParser(source_manager, context, *streamer, *asm_info));
  if (!parser) {
    return set_error("failed to create llvm asm parser", error);
  }

  auto target_parser = std::unique_ptr<llvm::MCTargetAsmParser>(
      target->createMCAsmParser(*subtarget_info, *parser, *instr_info, options));
  if (!target_parser) {
    return set_error("failed to create llvm target asm parser", error);
  }

  parser->setTargetParser(*target_parser);
  const bool had_error = parser->Run(false);
  if (had_error) {
    if (diagnostics.message.empty()) {
      diagnostics.message = "llvm assembler reported an error";
    }
    return set_error(diagnostics.message, error);
  }

  streamer->finish();

  auto *buffer = static_cast<std::uint8_t *>(std::malloc(object_storage.size()));
  if (buffer == nullptr) {
    return set_error("failed to allocate object buffer", error);
  }
  std::memcpy(buffer, object_storage.data(), object_storage.size());
  *bytes = buffer;
  *length = object_storage.size();
  return true;
}

extern "C" void binlex_llvm_free_bytes(std::uint8_t *bytes) {
  std::free(bytes);
}

extern "C" void binlex_llvm_free_error(char *error) { std::free(error); }
